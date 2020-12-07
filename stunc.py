#!/usr/bin/env vpython3
import sys
import socket
import json
from sturn import stun
from sturn.stun import agent, attributes ,authentication

maxMessageSize = 1280
class Demo:
    def __init__(self, host, port, sourceip='0.0.0.0', sourceport=54320, timeout=5):
        self.host = host
        self.port = port
        self.sourceip = sourceip
        self.sourceport = sourceport
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.conn.settimeout(timeout)
        self.conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.conn.bind((sourceip, sourceport))

    def close(self):
        self.conn.close()

    def Request(self, data):
        self.conn.sendto(data, (self.host, self.port))
        resp = self.conn.recvfrom(maxMessageSize)
        #import pdb; pdb.set_trace()
        resp = agent.Message.decode(resp[0])
        return resp

def main():
    with open(sys.argv[1]) as fp:
        config = json.load(fp)
    cls = Demo(config['turnhost'], config['turnport'])
    req = agent.Message.encode(stun.METHOD_BINDING, stun.CLASS_REQUEST)
    resp = cls.Request(req)

    address = resp.get_attr(stun.ATTR_XOR_MAPPED_ADDRESS, stun.ATTR_MAPPED_ADDRESS)
    print('public address: family:{} port:{} address:{}'.format(address.family, address.port, address.address))

main()
