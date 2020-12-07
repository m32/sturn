#!/usr/bin/env vpython3
import os
import sys
import json
import logging.config
from twisted.internet import reactor
from sturn.turn.server import TurnUdpServer
from sturn.stun.authentication import LongTermCredentialMechanism


try:
    logging.config.fileConfig('logging.config')
except:
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")
    logging.exception("Failed to load 'logging.config' file")


with open(sys.argv[1]) as fp:
    config = json.load(fp)
software = config['software']
realm = bytes(config['realm'].encode('utf-8'))
users = config['users']
overrides = config.get('overrides') or {}
interface = config['turnhost']
port = config['turnport']

credential_mechanism = LongTermCredentialMechanism(realm, users)
server = TurnUdpServer(reactor, interface, port, software, credential_mechanism, overrides)
port = server.start()
logging.info("Started %r", server)
reactor.run()
