''' configs for honeypot '''
ID = 'server1'
BAN_CMD = "fail2ban-client set sshd banip "
SSH_PORT = 22
LOGFILE = '/var/log/honeypot.log'
HOST_VERSION = 'SSH-2.0-OpenSSH_9.4'
KEY = {'X-API-key': 'token_here'}
API_URL = 'https://example.com/api'
API = False
BAN = True
LOG = True
