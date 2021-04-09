''' configs for honeypot '''

BAN_CMD = "fail2ban-client set sshd banip "
HOST_KEY = rsakey.RSAKey.generate(2048)

SSH_PORT = 22
LOGFILE = '/var/log/honeypot.log'
