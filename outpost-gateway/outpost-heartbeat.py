"""
Outpost Gateway Heartbeat
Runs on Samsung — sends heartbeat to Mac Mini Outpost API every 30 seconds.
Pure stdlib — no dependencies.
"""
from urllib.request import urlopen, Request
from urllib.error import URLError
import json
import time
import socket
import os
import logging

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

OUTPOST_API  = os.environ.get('OUTPOST_API', 'http://192.168.0.107:8000')
GATEWAY_NODE = os.environ.get('GATEWAY_NODE', 'samsung')
GATEWAY_PORT = int(os.environ.get('GATEWAY_PORT', '80'))
INTERVAL     = 30


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('192.168.0.1', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '192.168.0.105'


def send_heartbeat(ip):
    payload = json.dumps({
        'node': GATEWAY_NODE,
        'ip':   ip,
        'port': GATEWAY_PORT,
        'live': True
    }).encode()
    req = Request(
        OUTPOST_API + '/api/v1/gateway/heartbeat',
        data=payload,
        headers={'Content-Type': 'application/json'},
        method='POST'
    )
    try:
        with urlopen(req, timeout=5) as resp:
            resp.read()
            logger.info('Heartbeat sent — %s:%d', ip, GATEWAY_PORT)
            return True
    except URLError as e:
        logger.warning('Heartbeat failed — outpost unreachable: %s', e)
        return False
    except Exception as e:
        logger.warning('Heartbeat error: %s', e)
        return False


if __name__ == '__main__':
    logger.info('Gateway heartbeat starting — target: %s', OUTPOST_API)
    while True:
        ip = get_local_ip()
        send_heartbeat(ip)
        time.sleep(INTERVAL)
