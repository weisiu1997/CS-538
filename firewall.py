from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr
from collections import namedtuple
import os

log = core.getLogger()

class Firewall (EventMixin):

    def __init__ (self):
        self.listenTo(core.openflow)
        log.debug("Enabling Firewall Module")

    def _handle_ConnectionUp (self, event):
        ''' Add your logic here ... '''

        
        msg = of.ofp_match()
        msg.dl_src = EthAddr("00:00:00:00:00:02")
        msg.dl_dst = EthAddr("00:00:00:00:00:03")

        ofmsg = of.ofp_flow_mod()
        ofmsg.match = msg
        event.connection.send(ofmsg)

        log.debug("Firewall rules installed on %s", dpidToStr(event.dpid))

def launch ():
    core.registerNew(Firewall)
