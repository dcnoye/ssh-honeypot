#!/usr/bin/env python3
""" 
    SSH Honeypot Server that will ban all IP's via fail2ban

"""
from binascii import hexlify
import os
import re
import socket
import sys
import threading
from datetime import datetime
import paramiko

ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
BAN_CMD = "fail2ban-client set sshd banip "
O_TIME = str(datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f'))
HOST_KEY = paramiko.rsakey.RSAKey.generate(2048)

O_IP = ""
SSH_PORT = 22
LOGFILE = '/var/log/honeypot.log'
LOGFILE_LOCK = threading.Lock()


class Server(paramiko.ServerInterface):
    '''  We are failing every ssh login attempt and anyone that grab the banner,
         Then logging everything to aggregate and later review '''
    def __init__(self):
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        LOGFILE_LOCK.acquire()
        try:
            user_pass = '{0}:{1}'.format(username, password)
            honeylog(user_pass)
        finally:
            LOGFILE_LOCK.release()
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        LOGFILE_LOCK.acquire()
        try:
            user_pass = '{0}:{1}'.format(username, hexlify(key.get_fingerprint()))
            honeylog(user_pass)
        finally:
            LOGFILE_LOCK.release()
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password,publickey'


def honeyp(client):
    '''  Setup custom sshd server '''
    try:
        transport = paramiko.Transport(client)
        transport.add_server_key(HOST_KEY)
        transport.local_version = 'SSH-2.0-OpenSSH_9.4'
        server = Server()
        transport.start_server(server=server)
        channel = transport.accept(1)

        if channel is not None:
            channel.close()
    except Exception as e:
        print("ERROR: Transport handling", e)

def ban(remoteip):
    '''  send offending ip to system fail2ban '''
    result = ip_pattern.search(remoteip)
    if result:
        os.system(BAN_CMD + result.group(0))


def honeylog(user_pass):
    '''  log time ip and user credentials  '''
    try:
        new_entry = '{0} {1} {2} \n'.format(O_TIME, O_IP, user_pass)
        logf = open(LOGFILE, "a")
        logf.write(new_entry)
        logf.close()
    except Exception as e:
        print("ERROR: Log Handling", e)


def main():
    '''  We are failing every attempt, and logging as we go '''
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('', SSH_PORT))
        server_socket.listen(1)

        while True:
            try:
                cs, client_addr = server_socket.accept()
                print(client_addr[0])
                x = threading.Thread(target=honeyp, args=(cs,))
                x.start()
                global O_IP
                O_IP = client_addr[0]
                ban(client_addr[0])
            except Exception as e:
                print("ERROR: Client handling", e)

    except Exception as e:
        print("ERROR: Failed to create socket", e)
        sys.exit(1)


if __name__ == '__main__':
    main()
