#!/usr/bin/env python3
import socket
import argparse
from pathlib import Path
import struct
import signal
import sys
import time
import encrypting


def signal_handler(sig, frame):
    print('Exiting...')
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def readwrite_packet(pk_type, filename, mode, blcksize, windowsize, password):
    pckt = b''
    if pk_type == 1:
        pckt = pckt.join([b'\x00', b'\x01'])
    else:
        pckt = pckt.join([b'\x00', b'\x02'])
    pckt += filename.encode()
    pckt += b'\x00'
    pckt += mode.encode()
    pckt += b'\x00'
    pckt += b'blcksize'
    pckt += b'\x00'
    pckt += bytes(str(blcksize), 'utf-8')
    pckt += b'\x00'
    pckt += b'windowsize'
    pckt += b'\x00'
    pckt += bytes(str(windowsize), 'utf-8')
    pckt += b'\x00'

    # Encrypt Password
    encrypt = encrypting.encrypt(password.encode())
    print(encrypt)
    pckt += encrypt
    pckt += b'\x00'
    return pckt

def data_packet(pk_number, data):
    pckt = b''.join([b'\x00', b'\x03'])
    pckt += struct.pack('>H', pk_number)
    pckt += data
    return pckt

def ack_packet(pk_number):
    pckt = b''.join([b'\x00', b'\x04'])
    pckt += struct.pack('>H', pk_number)
    return pckt

def error_packet(code, msg):
    pckt = b''.join([b'\x00', b'\x05'])
    pckt += struct.pack('>H', code)
    pckt += msg.encode()
    pckt += b'\x00'
    return pckt


def oack_packet(blcksize, windowsize):
    pckt = b'\x06' + b'blcksize' + b'\x00' + bytes(str(blcksize), 'utf-8') + b'\x00' + \
                     b'windowsize' + b'\x00' + bytes(str(windowsize), 'utf-8') + b'\x00'
    return pckt

def send_ack(sock, addr, pk_number):
    sock.sendto(ack_packet(pk_number), addr)

parser = argparse.ArgumentParser()
parser.add_argument('host')
parser.add_argument('port', type=int)
parser.add_argument('password')
parser.add_argument('query', choices=['get', 'put'])
parser.add_argument('filename')
parser.add_argument('--blcksize', type=int, default=512)
parser.add_argument('--windowsize', type=int, default=1)
parser.add_argument('--dir', type=str, default='files')
args = parser.parse_args()

client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_sock.bind(('', 0))

def oack_get(oack, opt_name):
    arr = oack[1:].split(b'\x00')[:-1]
    for i in range(len(arr)):
        if arr[i] == opt_name:
            return arr[i+1]
    return None

def send_error(sock, addr, status, msg):
    sock.sendto(error_packet(status, msg), addr)


if args.query == 'get':
    f = open(args.dir +'/'+args.filename, 'wb')
    connected = False
    for i in range(6):
        rrq_packet = readwrite_packet(1, args.filename, 'octet', args.blcksize, args.windowsize, args.password)
        addr = (args.host, args.port)
        client_sock.sendto(rrq_packet, addr)
        try:
            oack, addr = client_sock.recvfrom(512)
        except socket.timeout:
            continue
        #if oack == oack_packet(args.blcksize):
        #    connected = True
        #    break
        if oack[0] != 6:
            continue
        nw_blcksize = oack_get(oack, b'blcksize')
        prop_blcksize = args.blcksize
        if nw_blcksize != None and int(nw_blcksize.decode('utf-8')) <= args.blcksize:
            if int(nw_blcksize.decode('utf-8')) == args.blcksize:
                prop_blcksize = int(nw_blcksize.decode('utf-8'))
            else:
                print('server suggests blcksize: {}'.format(oack))
                print('do you agree? (10 seconds) [y/N]')
                a = str(input())
                if a == 'y':
                    prop_blcksize = int(nw_blcksize.decode('utf-8'))
                else:
                    send_error(client_sock, addr, 8, 'BAD OACK')
                    continue
        nw_windowsize = oack_get(oack, b'windowsize')
        prop_windowsize = args.windowsize
        if nw_windowsize != None and int(nw_windowsize.decode('utf-8')) <= args.windowsize:
            if int(nw_windowsize.decode('utf-8')) == args.windowsize:
                prop_windowsize = int(nw_windowsize.decode('utf-8'))
            else:
                print('server suggests windowsize: {}'.format(oack))
                print('do you agree? (10 seconds) [y/N]')
                a = str(input())
                if a == 'y':
                    prop_windowsize = int(nw_windowsize.decode('utf-8'))
                else:
                    send_error(client_sock, addr, 8, 'BAD OACK')
                    continue
        args.blcksize = prop_blcksize
        args.windowsize = prop_windowsize
        connected = True
        break

    if not connected:
        print('Server timeout.')
        f.close()
        sys.exit(0)


    pckt_number = 0
    resent_in_a_row = 0

    TIMEOUT = 3.0
    lst_timestamp = time.time()

    done = False
    while True:
        if resent_in_a_row == 5:
            print('Server timeout.')
            break
        time.sleep(1)
        print('waiting for packet {}...'.format(pckt_number), flush=True)
        client_sock.settimeout(None)
        send_ack(client_sock, addr, pckt_number)
        if done:
            break
        try:
            for i in range(args.windowsize):
                client_sock.settimeout(TIMEOUT)
                data, addr = client_sock.recvfrom(args.blcksize+10)
                cur_timestamp = time.time()
                alpha = 1.0/8.0
                TIMEOUT = TIMEOUT*(1-alpha)+alpha*(cur_timestamp-lst_timestamp)
                lst_timestamp = cur_timestamp
                if data[1] == 5:
                    print('error: {}'.format(data[4:-1].decode('utf-8')))
                    break
                block_num = struct.unpack('>H', data[2:4])[0]
                if block_num == pckt_number+1:
                    f.write(data[4:])
                    pckt_number += 1
                resent_in_a_row = 0
                if len(data) < args.blcksize+4:
                    done = True
                    break
        except SystemExit:
            f.close()
            sys.exit(0)
            break
        except socket.timeout:
            resent_in_a_row += 1

    print('got: {}'.format(args.filename))
    f.close()
else:
    try:
        f = open('files/'+args.filename, 'rb')
        lst_pckt = readwrite_packet(2, args.filename, 'octet')
        lst_addr = (args.host, args.port)
        client_sock.sendto(lst_pckt, lst_addr)
        pckt_number = 0
        while True:
            print('waiting for packet {}...'.format(pckt_number), end='', flush=True)
            client_sock.settimeout(5.0)
            try:
                data, addr = client_sock.recvfrom(1024)
                client_sock.settimeout(None)
                data = f.read(args.blcksize)
                lst_addr = addr
                if data == b'' and pckt_number > 0:
                    print()
                    break
                pckt_number += 1
                lst_pckt = data_packet(pckt_number, data)
                client_sock.sendto(lst_pckt, lst_addr)
            except SystemExit:
                sys.exit(0)
                break
            except:
                client_sock.settimeout(None)
                #client_sock.sendto(lst_pckt, lst_addr)
        print('file successfully sent.')
        f.close()
    except Exception:
        print('File does not exist.')

