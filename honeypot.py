#!/usr/bin/env python3
"""
SSH Honeypot Server that will ban all IP's via fail2ban

"""
from binascii import hexlify
import sys
import os
import re
import time
from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from threading import Lock, Event, Thread
from datetime import datetime
from paramiko import rsakey, ServerInterface, AUTH_FAILED, Transport
import config as CONFIG

LOGFILE_LOCK = Lock()


class Server(ServerInterface):
    '''
    We fail and ban every ssh login attempt and any banner grab.
    Then logging everything to aggregate and later review
    '''
    def __init__(self):
        self.event = Event()

    def check_auth_password(self, username, password):
        LOGFILE_LOCK.acquire()
        try:
            honeylog('{0}:{1}'.format(username, password))
        finally:
            LOGFILE_LOCK.release()
        return AUTH_FAILED

    def check_auth_publickey(self, username, key):
        LOGFILE_LOCK.acquire()
        try:
            honeylog('{0}:{1}'.format(username, hexlify(key.get_fingerprint())))
        finally:
            LOGFILE_LOCK.release()
        return AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password,publickey'


def honeypot(client):
    '''  Setup custom sshd server '''
    try:
        transport = Transport(client)
        transport.add_server_key(CONFIG.HOST_KEY)
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
    try:
        result = ipcheck(remoteip)
        if result:
            time.sleep(1)
            os.system(CONFIG.BAN_CMD + result.group(0))
    except Exception as e:
        print("ERROR: Ban  handling", e)


def honeylog(data):
    '''  log time, ip or user credentials  '''
    o_time = str(datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f'))
    o_entry = '{0} {1} \n'.format(o_time, data)
    try:
        logf = open(CONFIG.LOGFILE, "a")
        logf.write(o_entry)
        logf.close()
    except Exception as e:
        print("ERROR: Log Handling", e)

def ipcheck(ipmaybe):
    ''' check if it's a valid ip4 address ''' #TODO: check for ipv6
    x = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    return(x.search(remoteip))
        


def main():
    '''  We are failing every attempt, and logging as we go '''
    try:
        sock_s = socket(AF_INET, SOCK_STREAM)
        sock_s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        sock_s.bind(('', CONFIG.SSH_PORT))
        sock_s.listen()

        while True:
            try:
                conn, client_addr = sock_s.accept()
                x_thread = Thread(target=honeypot, args=(conn,))
                x_thread.start()

                ban(client_addr[0])
                honeylog(client_addr[0])

            except Exception as e:
                print("ERROR: Client handling", e)

    except Exception as e:
        print("ERROR: Failed to create socket", e)
        sys.exit(1)


if __name__ == '__main__':
    main()
