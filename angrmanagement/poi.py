from PySide2 import QtCore
from queue import Queue
import time
import socket

actions = Queue()
remote_actions = Queue()


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


def select_func(func):
    print("User selected function {} at 0x{:x}".format(func, func.addr))
    actions.put(HumanPOIFunc(func))


def select_addr(addr):
    print("User selected address 0x{:x}".format(addr))
    actions.put(HumanPOIAddr(addr))


def add_rename(addr):
    print("User renamed label at 0x{:x}".format(addr))
    actions.put(HumanPOIAddr(addr))


class UpdateWorker(QtCore.QThread):
    updatePOIs = QtCore.Signal(HumanPOI)

    def __init__(self, main_window):
        QtCore.QThread.__init__(self)
        self.mw = main_window
        fake_remote_actions = [0x0040085a, 0x0040085a, 0x0040085a, 0x0040085a, 0x0040085a, 0x0040085a, 0x0040085a,
                               0x0040085a, 0x0040085a, 0x0040085a, 0x0040085a, 0x0040085a, 0x0040085a, 0x0040085a,
                               0x0040085b, 0x0040085b, 0x0040085b, 0x0040085b, 0x0040085e]

        for a in fake_remote_actions:
            remote_actions.put(HumanPOIAddr(a))

    def run(self):
        while True:
            time.sleep(1)
            # Send out updates on our user
            if not actions.empty():
                h = actions.get()
                print("Sending update: 0x{}".format(h.addr))
                self.updatePOIs.emit(h)

            # Get updates about other users
            if not remote_actions.empty():
                h = remote_actions.get()
                print("Got update at addr 0x{}".format(h.addr))
                self.mw.workspace.views_by_category['disassembly'][0].current_graph.add_inst_interest(h.addr)

