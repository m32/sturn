#!/usr/bin/env vpython3
import socket
from sturn import utils
from sturn import turn
from sturn.turn import attributes as turnattributes
from sturn import stun
from sturn.stun import agent, attributes ,authentication

class LongTermCredentialMechanism(object):
    """
    :see: http://tools.ietf.org/html/rfc5389#section-10.2
    """
    def __init__(self, nonce, realm, username, password):
        self.nonce = nonce
        self.realm = realm
        self.username = username
        self.hmac = utils.ha1(username, self.realm, password)

    def update(self, msg):
        msg.add_attr(attributes.Username, self.username)
        msg.add_attr(attributes.Nonce, self.nonce)
        msg.add_attr(attributes.Realm, self.realm)
        msg.add_attr(attributes.MessageIntegrity, self.hmac)

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
        print('req', data.format())
        self.conn.sendto(data, (self.host, self.port))
        resp = self.conn.recvfrom(maxMessageSize)
        #import pdb; pdb.set_trace()
        resp = agent.Message.decode(resp[0])
        print('resp', resp.format())
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
            request.add_attr(turn.ATTR_LIFETIME, time_to_expiry)
        if dont_fragment:
            request.add_attr(turn.ATTR_DONT_FRAGMENT)
        if even_port is not None and not reservation_token:
            request.add_attr(turn.ATTR_EVEN_PORT, even_port)
        if reservation_token:
            request.add_attr(turn.ATTR_RESERVATION_TOKEN, even_port)
        resp = self.Request(request)
        return request, resp

def main():
    cls = Demo('192.168.2.104', 3478, '192.168.2.104', 54320)
    #cls = Demo('drugi.trisoft.com.pl', 3478, '192.168.2.104', 54320)
    req = agent.Message.encode(stun.METHOD_BINDING, stun.CLASS_REQUEST)
    resp = cls.Request(req)
    req, resp = cls.Allocate()

    nonce = resp.get_attr(stun.ATTR_NONCE)
    realm = resp.get_attr(stun.ATTR_REALM)
    LongTermCredentialMechanism(nonce, realm, 'passuser', 'password').update(req)
    req.add_attr(attributes.Fingerprint)
    resp = cls.Request(req)

main()
