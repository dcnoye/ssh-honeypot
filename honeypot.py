#!/usr/bin/env python3
"""
SSH Honeypot Server that will ban all IP's via fail2ban

"""

from paramiko.py3compat import b, u, encodebytes, decodebytes

from binascii import hexlify
import sys
import os
import re
import time
import logging
import requests
from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from threading import Lock, Thread
from datetime import datetime
from paramiko import rsakey, ServerInterface, AUTH_FAILED, Transport
import config as CONFIG

LOGFILE_LOCK = Lock()
HOST_KEY = rsakey.RSAKey.generate(2048)

# Setup logging
logging.basicConfig(filename=CONFIG.LOGFILE, level=logging.INFO,
                    format='%(asctime)s - %(message)s', datefmt='%Y-%m-%dT%H:%M:%S.%f')



class Server(ServerInterface):
    ''' Customized paramiko to fail every attempt, then log.
    '''
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        ServerInterface.__init__(self)

    def check_auth_password(self, username, password):
        with LOGFILE_LOCK:
            honeylog(f'{self.ip} {username}:{password}')
        return AUTH_FAILED

    def check_auth_publickey(self, username, key):
        with LOGFILE_LOCK:
            honeylog(f'{self.ip} {username}:{key.get_fingerprint()}')
        return AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password,publickey'


def honeypot(client, ip, port):
    '''  Setup custom sshd server '''
    try:
        transport = Transport(client)
        transport.add_server_key(HOST_KEY)
        transport.local_version = CONFIG.HOST_VERSION
        server = Server(ip, port)
        transport.start_server(server=server)
        channel = transport.accept(1)

        if channel is not None:
            channel.close()
    except Exception as e:
        logging.error("ERROR: Transport handling - %s", str(e))


def ban(remoteip):
    '''  send offending ip to system fail2ban '''
    try:
        result = ipcheck(remoteip)
        if result:
            time.sleep(1)
            os.system(CONFIG.BAN_CMD + result.group(0))
    except Exception as e:
        logging.error("ERROR: Ban handling - %s", str(e))


def honeylog(data):
    """Log time, ip or user credentials"""
    if CONFIG.LOG:
        logging.info(data)


def ipcheck(ipmaybe):
    ''' check if it's a valid ip4 address '''
    # TODO: check for ipv6
    x_regex = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    return x_regex.search(ipmaybe)


def phonehome(data):
    '''  Send data to dashboard API '''
    # TODO: cleanup
    o_time = str(datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f'))
    payload = {'name': CONFIG.ID, 'date': o_time, 'data': data}
    requests.post(CONFIG.API_URL, data=payload, headers=CONFIG.KEY)


def main():
    '''
    By default, we fail & ban every login attempt and any banner grabbing.
    Then logging everything to aggregate and later review.

    '''
    print("Starting honeypot on port ",CONFIG.SSH_PORT)
    try:
        sock_s = socket(AF_INET, SOCK_STREAM)
        sock_s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        sock_s.bind(('', CONFIG.SSH_PORT))
        sock_s.listen(1)

        while True:
            try:
                conn, client_addr = sock_s.accept()
                x_thread = Thread(target=honeypot, args=(conn, client_addr[0], client_addr[1]))
                x_thread.start()
                if CONFIG.BAN is True:
                    ban(client_addr[0])
                if CONFIG.API is True:
                    phonehome(client_addr[0])

            except Exception as e:
                logging.error("ERROR: Client handling - %s", str(e))
                conn.close()

    except Exception as e:
        logging.error("ERROR: Failed to create socket - %s", str(e))
        sys.exit(1)


if __name__ == '__main__':
    main()
