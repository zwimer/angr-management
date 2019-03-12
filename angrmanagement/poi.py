from PySide2 import QtCore
from queue import Queue
import time
import socket

#########################################################
from angr.knowledge_plugins.plugin import KnowledgeBasePlugin


class POIs(KnowledgeBasePlugin):
    # TODO: Save POI objects rather than just interest val
    # TODO: With HumanPOIFunc, use addr so names don't matter
    # TODO: Track unique members so interest count is weighted (2 people = bigger changes in color, etc)

    def __init__(self, kb):
        self._kb = kb
        self._interest = {}

    def __iter__(self):
        return self._interest.__iter__()

    def __getitem__(self, k):
        ret = 0 # default
        try:
            ret = self._interest[k]
        except KeyError:
            pass

        return ret

    def __setitem__(self, k, v):
        del self[k]
        self._interest[k] = v

    def __delitem__(self, k):
        if k in self._interest:
            del self._interest[k]

    def __contains__(self, k):
        return k in self._interest

    def get(self, addr):
        return self[addr]

    def copy(self):
        o = POIs(self._kb)
        o._interest = {k: v for k, v in self._interest.items()}


KnowledgeBasePlugin.register_default('pois', POIs)


#########################################################

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
        fake_remote_actions = \
            [0x0040085a, 0x0040085b, 0x0040085e,  # first three addrs in main(), first should have 12
             0x00400750,  # not in first view, should error in add_inst_interest()
             0x0040085a, 0x0040085a, 0x0040085a, 0x0040085a, 0x0040085a,  # repeats of above
             0x0040085a, 0x0040085a, 0x0040085a, 0x0040085a, 0x0040085a,  # repeats of above
             0x0040085a, 0x0040085b, 0x0040085e, 0x0040085e, 0x0040085e]  # repeats of above

        for a in fake_remote_actions:
            self.remote_actions.put(HumanPOIAddr(a))

        ###################################

    def run(self):
        # We need to get the POI plugin. If it's not there, it's because
        # the user hasn't loaded a binary or the project hasn't done its
        # analysis yet.
        pp = None
        while pp is None:
            if self.mw.workspace.instance.cfg is not None:
                pp = self.mw.workspace.instance.cfg.kb.get_plugin('pois')
            else:
                time.sleep(1) # wait a second for analysis to finish

        def add_poi_interest(key):
            if key in pp:
                pp[key] += 1
            else:
                pp[key] = 1

        while True:
            need_cg_update = False
            need_fv_update = False
            # Get the current view (func graph vs linear)
            cg = self.mw.workspace.views_by_category['disassembly'][0].current_graph

            # Get updates about other users
            if not self.remote_actions.empty():
                new_poi = self.remote_actions.get()

                print("Got update at addr {:#10x}".format(new_poi.addr))
                add_poi_interest(new_poi.addr)
                need_cg_update = cg.add_inst_interest(new_poi.addr)

            # Send out updates on our user
            if not self.actions.empty():
                new_poi = self.actions.get()
                if not isinstance(new_poi, HumanPOIFunc) and new_poi.addr:
                    print("Sending update: {:#10x}".format(new_poi.addr))
                    need_cg_update = cg.add_inst_interest(new_poi.addr)
                    add_poi_interest(new_poi.addr)
                elif isinstance(new_poi, HumanPOIFunc):
                    print("Sending update: func {}".format(new_poi.func.name))
                    add_poi_interest(new_poi.func.name)
                    fv = self.mw.workspace.views_by_category['functions'][0]
                    fv.reload()

                self.updatePOIs.emit(new_poi)

            if need_cg_update:
                cg.viewport().update()

            time.sleep(0.5)


# Called throughout the UI to add a POI. The caller creates the POI object.
def add_new_poi(poi):
    if not isinstance(poi, HumanPOIFunc) and poi.addr:
        print("New user POI @ {:#10x}".format(poi.addr))
        UpdateWorker.actions.put(poi)
    elif isinstance(poi, HumanPOIFunc):
        print("New user POI @ {:#10x} (function '{}')".format(poi.addr, poi.func.name))
        UpdateWorker.actions.put(poi)
    else:
        print("**NO ADDRESS** New user POI")  # Unsure how/if we'll use POIs without an address

