#!/usr/bin/env vpython3
import sys
import time
import binascii
import socket
import select
import hashlib
import hmac

from sturn import utils
from sturn import turn
from sturn.turn import attributes as turnattributes
from sturn import stun
from sturn.stun import agent, attributes ,authentication

import json
import io

class LongTermCredentialMechanism(object):
    """
    :see: http://tools.ietf.org/html/rfc5389#section-10.2
    """
    def __init__(self, username, password, nonce, realm, authsecret=None):
        self.nonce = nonce
        self.realm = realm
        if authsecret:
            exp_time = 3600 * 24 # one day
            if username:
                username = "%d:%s" % (time.time() + exp_time, username)
            else:
                username = "%d" % (time.time() + exp_time)

            h = hmac.new(
                authsecret.encode('utf-8'),
                username.encode('utf-8'),
                hashlib.sha1
            )
            password = h.digest()
            password = binascii.b2a_base64(password).strip().decode()

        self.username = username
        self.hmac = utils.ha1(username, self.realm, password)

    def update(self, msg):
        msg.add_attr(attributes.Username, self.username)
        msg.add_attr(attributes.Nonce, self.nonce)
        msg.add_attr(attributes.Realm, self.realm)
        msg.add_attr(attributes.MessageIntegrity, self.hmac)

maxMessageSize = 1280
class Demo:
    def __init__(self, host, port, sourceip='0.0.0.0', sourceport=54321, timeout=5):
        self.host = host
        self.port = port
        self.sourceip = sourceip
        self.sourceport = sourceport
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.conn.settimeout(timeout)
        self.conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.conn.bind((sourceip, sourceport))
        self.ltc = None
        self.running = False

    def close(self):
        self.conn.close()

    def Request(self, req, resp=True):
        if self.ltc:
            self.ltc.update(req)
            req.add_attr(attributes.Fingerprint)
        self.conn.sendto(req, (self.host, self.port))
        if resp:
            resp = self.conn.recvfrom(maxMessageSize)
            resp = agent.Message.decode(resp[0])
            #print('resp:', resp.format())
            return resp

    def Allocate(self,
        transport=turn.TRANSPORT_UDP, time_to_expiry=None,
        dont_fragment=False, even_port=None, reservation_token=None
    ):
        """
        :param even_port: None | 0 | 1 (1==reserve next highest port number)
        :see: http://tools.ietf.org/html/rfc5766#section-6.1
        """
        request = agent.Message.encode(turn.METHOD_ALLOCATE, stun.CLASS_REQUEST)
        request.add_attr(turnattributes.RequestedTransport, transport)
        if time_to_expiry:
            request.add_attr(turnattributes.Lifetime, time_to_expiry)
        if dont_fragment:
            request.add_attr(turnattributes.DontFragment)
        if even_port is not None and not reservation_token:
            request.add_attr(turnattributes.EvenPort, even_port)
        if reservation_token:
            request.add_attr(turnattributes.ReservationToken, even_port)
        resp = self.Request(request)
        return request, resp

    def Refresh(self, time_to_expiry=None):
        """
        :see: http://tools.ietf.org/html/rfc5766#section-6
        """
        request = agent.Message.encode(turn.METHOD_REFRESH, stun.CLASS_REQUEST)
        if time_to_expiry is not None:
            request.add_attr(turnattributes.Lifetime, time_to_expiry)
        resp = self.Request(request, time_to_expiry is None and time_to_expiry != 0)
        return request, resp

    def Secure(self, req, resp, username, userpass, secret):
        nonce = resp.get_attr(stun.ATTR_NONCE)
        realm = resp.get_attr(stun.ATTR_REALM)
        self.ltc = LongTermCredentialMechanism(
            username, userpass,
            nonce, realm,
            secret
        )

    def Permit(self, address, port):
        request = agent.Message.encode(turn.METHOD_CREATE_PERMISSION, stun.CLASS_REQUEST)
        request.add_attr(turnattributes.XorPeerAddress, 1, port, address)
        resp = self.Request(request)
        return request, resp

    def connect(self, username, userpass, secret):
        req = agent.Message.encode(stun.METHOD_BINDING, stun.CLASS_REQUEST)
        self.Request(req)

        req, resp = self.Allocate(time_to_expiry=1200)
        nonce = resp.get_attr(stun.ATTR_NONCE)
        realm = resp.get_attr(stun.ATTR_REALM)
        self.ltc = LongTermCredentialMechanism(
            username, userpass,
            nonce, realm,
            secret
        )
        resp = self.Request(req)
        self.lifetime = resp.get_attr(turn.ATTR_LIFETIME)
        puba = resp.get_attr(turn.ATTR_XOR_RELAYED_ADDRESS, stun.ATTR_MAPPED_ADDRESS)
        mapa = resp.get_attr(stun.ATTR_XOR_MAPPED_ADDRESS, stun.ATTR_MAPPED_ADDRESS)
        self.config = {
            'public': [puba.family, puba.address, puba.port],
            'mapped': [mapa.family, mapa.address, mapa.port],
        }

    def done(self):
        self.Refresh(0)
        self.close()

    def setupc(self):
        clsd = json.load(io.open('turnc-udpd.json','r'))
        req, resp = self.Permit(clsd['mapped'][1], clsd['mapped'][2])

    def runc(self):
        self.running = True
        print('*'*20, 'runc')

        config = json.load(io.open('turnc-udpd.json','r'))['mapped']
        data = b'ala ma kota'

        req = agent.Message.encode(turn.METHOD_SEND, stun.CLASS_INDICATION)
        req.add_attr(turnattributes.XorPeerAddress, config[0], config[2], config[1])
        req.add_attr(turnattributes.Data, data)
        print('*'*20, 'send', config)
        self.Request(req, False)
        time.sleep(1)
        self.running = False

    def setupd(self):
        clsd = json.load(io.open('turnc-udpc.json','r'))
        req, resp = self.Permit(clsd['mapped'][1], clsd['mapped'][2])

    def rund(self):
        self.running = True
        print('*'*20, 'rund')
        tte = self.lifetime.time_to_expiry // 10
        while True:
            sys.stdout.write('.%d'%tte)
            sys.stdout.flush()
            ioe = select.select([self.conn], [], [], 1)
            if ioe[0]:
                data = self.conn.recvfrom(maxMessageSize)
                print('*'*20, 'recv:', data)
                break
            else:
                tte -= 1
                if tte < 110:
                    break
                    req, resp = self.Refresh(1200)
                    self.lifetime = resp.get_attr(turn.ATTR_LIFETIME)
                    print('refresh:', resp.format())
                    print('life time:', self.lifetime.time_to_expiry)
                    tte = self.lifetime.time_to_expiry // 10
        self.running = False

def main():
    with open(sys.argv[1]) as fp:
        config = json.load(fp)
    secret = config['realm']
    username = config['username']
    userpass = config['userpass']
    remotehost = config['turnhost']
    remoteport = config['turnport']

    clsd = Demo(remotehost, remoteport, '0.0.0.0', 54320)
    clsd.connect(username, userpass, secret)
    json.dump(clsd.config, io.open('turnc-udpd.json','w'))

    clsc = Demo(remotehost, remoteport, '0.0.0.0', 54321)
    clsc.connect(username, userpass, secret)
    json.dump(clsc.config, io.open('turnc-udpc.json','w'))

    clsd.setupd()
    clsc.setupc()

    import threading
    threading.Thread(target=clsd.rund).start()
    time.sleep(1)
    threading.Thread(target=clsc.runc).start()

    try:
        while clsc.running or clsd.running:
            time.sleep(1)
    finally:
        clsd.done()
        clsc.done()

main()
