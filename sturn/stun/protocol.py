import socket
import logging
from twisted.internet.protocol import DatagramProtocol
from . import stun
from .agent import Message
from .authentication import CredentialMechanism
from . import attributes

logger = logging.getLogger(__name__)


class StunUdpProtocol(DatagramProtocol):
    def __init__(self, reactor, interface, port, software, RTO=3., Rc=7, Rm=16):
        """
        :param port: UDP port to bind to
        :param RTO: Retransmission TimeOut (initial value)
        :param Rc: Retransmission Count (maximum number of request to send)
        :param Rm: Retransmission Multiplier (timeout = Rm * RTO)
        """
        self.reactor = reactor
        self.interface = interface
        self.port = port
        self.software = software
        self.RTO = .5
        self.Rc = 7
        self.timeout = Rm * RTO

        self._handlers = {
            # Binding handlers
            (stun.METHOD_BINDING, stun.CLASS_REQUEST):
                self._stun_binding_request,
            (stun.METHOD_BINDING, stun.CLASS_INDICATION):
                self._stun_binding_indication,
            (stun.METHOD_BINDING, stun.CLASS_RESPONSE_SUCCESS):
                self._stun_binding_success,
            (stun.METHOD_BINDING, stun.CLASS_RESPONSE_ERROR):
                self._stun_binding_error,
            }

    def start(self):
        port = self.reactor.listenUDP(self.port, self, self.interface)
        return port.port

    def datagramReceived(self, datagram, addr):
        msg_type = datagram[0] >> 6
        if msg_type == stun.MSG_STUN:
            try:
                msg = Message.decode(datagram)
            except Exception:
                logger.exception("Failed to decode STUN from %s:%d:", *addr)
                logger.debug(datagram.hex())
            else:
                if isinstance(msg, Message):
                    self._stun_received(msg, addr)
        else:
            logger.warning("Unknown message in datagram from %s:%d:", *addr)
            logger.debug(datagram.hex())

    def _stun_received(self, msg, addr):
        handler = self._handlers.get((msg.msg_method, msg.msg_class))
        if handler:
            logger.info("%s Received STUN", self)
            #logger.debug(msg.format())
            handler(msg, addr)
        else:
            logger.info("%s Received unrecognized STUN", self)
            logger.debug(msg.format())

    def _stun_unhandeled(self, msg, addr):
        logger.warning("%s Unhandeled message from %s:%d", self, *addr)
        logger.debug(msg.format())

    def _stun_binding_request(self, msg, addr):
        self._stun_unhandeled(msg, addr)

    def _stun_binding_indication(self, msg, addr):
        self._stun_unhandeled(msg, addr)

    def _stun_binding_success(self, msg, addr):
        self._stun_unhandeled(msg, addr)

    def _stun_binding_error(self, msg, addr):
        self._stun_unhandeled(msg, addr)


