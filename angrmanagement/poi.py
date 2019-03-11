from PySide2 import QtCore
from queue import Queue
import time
import socket



class HumanPOI:
    def __init__(self, addr):
        self.tool = 'angr-management'
        self.addr = addr
        self.time = time.time()
        self.fqdn = socket.getfqdn()


class HumanPOIAddr(HumanPOI):
    def __init__(self, addr):
        super(HumanPOIAddr, self).__init__(addr)


class HumanPOIFunc(HumanPOI):
    def __init__(self, func):
        super(HumanPOIFunc, self).__init__(func.addr)
        self.func = func


class UpdateWorker(QtCore.QThread):
    updatePOIs = QtCore.Signal(HumanPOI)
    # Note that these are class attributes, not instance. There's no
    # reason to have several queues floating around... I think.
    actions = Queue()
    remote_actions = Queue()

    def __init__(self, main_window):
        QtCore.QThread.__init__(self)
        self.mw = main_window

        ###################################
        fake_remote_actions = [0x0040085a, 0x0040085b, 0x0040085e, 0x0040085a, 0x0040085a, 0x0040085a, 0x0040085a,
                               0x00400750, 0x0040085a, 0x0040085a, 0x0040085a, 0x0040085a, 0x0040085a, 0x0040085a,
                               0x0040085a, 0x0040085b, 0x0040085e, 0x0040085e, 0x0040085e]

        for a in fake_remote_actions:
            self.remote_actions.put(HumanPOIAddr(a))
        ###################################

    def run(self):
        while True:
            need_update = False
            cg = self.mw.workspace.views_by_category['disassembly'][0].current_graph
            # Get updates about other users
            if not self.remote_actions.empty():
                h = self.remote_actions.get()
                print("Got update at addr {:#10x}".format(h.addr))
                cg.add_inst_interest(h.addr)
                need_update = True

            # Send out updates on our user
            if not self.actions.empty():
                h = self.actions.get()
                print("Sending update: {:#10x}".format(h.addr))
                self.updatePOIs.emit(h)
                cg.add_inst_interest(h.addr)
                need_update = True

            if need_update:
                cg.viewport().update()

            time.sleep(0.1)


def add_new_poi(poi):
    if poi.addr:
        print("New user POI @ {:#10x}".format(poi.addr))
    else:
        print("**NO ADDRESS** New user POI") # Unsure how/if we'll use POIs without an address

    UpdateWorker.actions.put(poi)
