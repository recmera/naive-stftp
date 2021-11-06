#!/usr/bin/env python3
from os import pwrite
import socket
import argparse
from pathlib import Path
import struct
import sys
import time
import select
import encrypting

TIMEOUT=3.0
TIMEOUT_OACK=10.0

parser = argparse.ArgumentParser()
parser.add_argument('port', type=int)
parser.add_argument('--dir', type=str, default='/tmp')
parser.add_argument('--single_port', action='store_true')
args = parser.parse_args()


server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_sock.bind(('', args.port))

started_get = False


def data_packet(pk_number, data):
    pckt = b''.join([b'\x00', b'\x03'])
    pckt += struct.pack('>H', pk_number)
    pckt += data
    return pckt

def oack_packet(blcksize, windowsize):
    pckt = b'\x06' + b'blcksize' + b'\x00' + bytes(str(blcksize), 'utf-8') + b'\x00' + \
                     b'windowsize' + b'\x00' + bytes(str(windowsize), 'utf-8') + b'\x00'
    return pckt

def error_packet(code, msg):
    pckt = b''.join([b'\x00', b'\x05'])
    pckt += struct.pack('>H', code)
    pckt += bytes(msg, 'utf-8')
    pckt += b'\x00'
    return pckt

def send_error(client_addr, errorstatus):
    print('sending error...')

class Client:

    def __init__(self, name, blksize, windowsize, addr, sock):
        self.max_packet = 0
        self.blcksize = blcksize
        self.windowsize = windowsize
        self.addr = addr
        self.sock = sock
        self.resent_in_a_row = 0
        self.negotiating = True

        oack = oack_packet(blksize, windowsize)
        self.sock.sendto(oack, self.addr)
        self.timestamp = time.time()

    def senderror(self, errorstatus, msg):
        self.sock.sendto(error_packet(errorstatus, msg), self.addr)

    def process(self, pck_from_client):
        opcode = struct.unpack('>H', pck_from_client[:2])[0]
        if opcode == 5:
            print('got ERROR from {} : {}'.format(self.addr, pck_from_client[2:]))
            return True
        if opcode != 4:
            self.senderror(4, 'expected ACK packet')
            return True
        else:
            self.negotiating = False
            asked_number = struct.unpack('>H', pck_from_client[2:])[0]
            if asked_number > self.max_packet+1:
                self.senderror(4, 'wrong ACK packet')
                return True
            self.resent_in_a_row = 0
            packet_number = 1
            lst_sz = blcksize
            f = open(args.dir + '/' + name, 'rb')
            lst_window = False
            while packet_number <= asked_number:
                data = f.read(self.blcksize)
                if data == b'' and lst_sz != self.blcksize:
                    lst_window = True
                    break
                if len(data) < self.blcksize:
                    lst_window = True
                    break
                lst_sz = len(data)
                packet_number += 1
            if lst_window:
                f.close()
                print('Finished client {}'.format(self.addr))
                return True

            for i in range(self.windowsize):
                data = f.read(self.blcksize)
                if data == b'' and lst_sz != self.blcksize:
                    lst_window = True
                    break
                self.sock.sendto(data_packet(packet_number, data), self.addr)
                lst_sz = len(data)
                if packet_number >= self.max_packet:
                    self.max_packet = packet_number
                packet_number += 1

            self.timestamp = time.time()
            f.close()
            return False



clients = {}

def min_timeout():
    mn = -1
    for _, client in clients.items():
        if client.negotiating:
            if mn == -1 or client.timestamp+TIMEOUT_OACK < mn:
                mn = client.timestamp+TIMEOUT_OACK
        else:
            if mn == -1 or client.timestamp < mn:
                mn = client.timestamp
    return mn

def redunant_clients(timestamp):
    for addr, client in list(clients.items()):
        if not client.negotiating and client.timestamp+TIMEOUT < timestamp:
            print('Client {} timed out'.format(addr))
            del clients[addr]
        elif client.negotiating and client.timestamp+TIMEOUT_OACK+TIMEOUT < timestamp:
            print('Client {} timed out'.format(addr))
            del clients[addr]

if args.single_port:
    lst_timestamp = time.time()
    while True:
        timeout = min_timeout()
        if timeout != -1:
            timeout += TIMEOUT
            server_sock.settimeout(timeout-time.time())
        else:
            server_sock.settimeout(None)
        try:
            data, client_addr = server_sock.recvfrom(1024)
            cur_timestamp = time.time()
            alpha = 1.0/8.0
            TIMEOUT = (1-alpha)*TIMEOUT + alpha*(cur_timestamp-lst_timestamp)
            lst_timestamp = cur_timestamp
        except socket.timeout:
            redunant_clients(time.time())
            continue

        if client_addr not in clients:
            arr = data.split(b'\x00')[1:-1]
            if len(arr[0]) <= 1:
                bad = True
                send_error(client_addr, 1)
                continue

            if arr[0][0] != 1:
                send_error(client_addr, 0)
                continue
            print('starting for client {}'.format(client_addr))

            name = arr[0][1:].decode()
            print(name)
            password = encrypting.decrypt(arr[-1]).decode()
            print(arr)

            blcksize = 512
            windowsize = 1
            for i in range(len(arr)):
                if arr[i] == b'blcksize':
                    blcksize = int(arr[i+1].decode('utf-8'))
                if arr[i] == b'windowsize':
                    windowsize = int(arr[i+1].decode('utf-8'))

            print(blcksize, windowsize)

            try:
                clients[client_addr] = Client(name, blcksize, windowsize, client_addr, server_sock)
            except FileNotFoundError:
                send_error(client_addr, 1)
        else:
            todel = clients[client_addr].process(data)
            if todel:
                del clients[client_addr]
else:
    epoll = select.epoll()
    epoll.register(server_sock.fileno(), select.EPOLLIN)
    lst_timestamp = time.time()
    
    while True:
        timeout = min_timeout()
        if timeout != -1:
            timeout += TIMEOUT
            timeout = timeout-time.time()
        else:
            timeout = None
        for fileno, event in epoll.poll(timeout):
            if fileno == server_sock.fileno() and event & select.EPOLLIN:
                data, client_addr = server_sock.recvfrom(1024)
                cur_timestamp = time.time()
                alpha = 1.0/8.0
                TIMEOUT = (1-alpha)*TIMEOUT + alpha*(cur_timestamp-lst_timestamp)
                lst_timestamp = cur_timestamp
                arr = data.split(b'\x00')[1:-1]
                if len(arr[0]) <= 1:
                    bad = True
                    send_error(client_addr, 1)
                    continue

                if arr[0][0] != 1:
                    send_error(client_addr, 0)
                    continue
                print('starting for client {}'.format(client_addr))

                name = arr[0][1:].decode()
                print(name)

                password = encrypting.decrypt(arr[-1]).decode()

                if password == "admin":
                    print(arr)
                    
                    blcksize = 512
                    windowsize = 1
                    for i in range(len(arr)):
                        if arr[i] == b'blcksize':
                            blcksize = int(arr[i+1].decode('utf-8'))
                        if arr[i] == b'windowsize':
                            windowsize = int(arr[i+1].decode('utf-8'))

                    print(blcksize, windowsize)
                    client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    epoll.register(client_sock.fileno(), select.EPOLLIN)

                    try:
                        clients[client_sock.fileno()] = Client(name, blcksize, windowsize, client_addr, client_sock)
                    except FileNotFoundError:
                        send_error(client_addr, 1)
                else: 
                    print("Error de autentificación")



            elif fileno in clients and event & select.EPOLLIN:
                client = clients[fileno]
                data, client_addr = client.sock.recvfrom(1024)
                cur_timestamp = time.time()
                alpha = 1.0/8.0
                TIMEOUT = (1-alpha)*TIMEOUT + alpha*(cur_timestamp-lst_timestamp)
                lst_timestamp = cur_timestamp
                client.process(data)

