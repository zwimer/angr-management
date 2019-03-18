from PySide2 import QtCore
from queue import Queue
import time
import angr_comm_pb2

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


######################### DEBUG #########################
def _make_fake_remote_actions():
    import time
    fake_actions = []
    addrs = \
        [0x0040085a, 0x0040085b, 0x0040085e,  # first three addrs in main(), first should have 12
         0x00400750,  # not in first view, should error in add_inst_interest()
         0x0040085a, 0x0040085a, 0x0040085a, 0x0040085a, 0x0040085a,  # repeats of above
         0x0040085a, 0x0040085a, 0x0040085a, 0x0040085a, 0x0040085a,  # repeats of above
         0x0040085a, 0x0040085b, 0x0040085e, 0x0040085e, 0x0040085e]  # repeats of above
    for addr in addrs:
        msg = angr_comm_pb2.HumanPOI()
        msg.tool = 'angr-management'
        msg.timestamp = int(time.time())
        msg.source = 'TEST_REMOTE_SOURCE'
        msg.file = 'TEST_BINARY_NAME' # testlib/test_preload
        msg.code_location = addr
        msg.loc_type = angr_comm_pb2.HumanPOI.INST_ADDR
        fake_actions.append(msg)

    # main function
    msg = angr_comm_pb2.HumanPOI()
    msg.tool = 'angr-management'
    msg.timestamp = int(time.time())
    msg.source = 'TEST_REMOTE_SOURCE'
    msg.file = 'TEST_BINARY_NAME'   # testlib/test_preload
    msg.code_location = 0x0040085a
    msg.loc_type = angr_comm_pb2.HumanPOI.FUNC_ADDR
    fake_actions.append(msg)
    return fake_actions
#########################################################

class UpdateWorker(QtCore.QThread):
    updatePOIs = QtCore.Signal(int)
    # Note that these are class attributes, not instance. There's no
    # reason to have several queues floating around... I think.
    local_pois = Queue()
    remote_pois = Queue()

    def __init__(self, main_window):
        QtCore.QThread.__init__(self)
        self.mw = main_window

        ######################### DEBUG #########################
        remotes = _make_fake_remote_actions()
        for r in remotes:
            self.remote_pois.put(r)
        #########################################################

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

            # Get the current view (func graph vs linear)
            cg = self.mw.workspace.views_by_category['disassembly'][0].current_graph

            new_poi = None
            # Handle our own updates before pulling in others'
            if not self.local_pois.empty():
                new_poi = self.local_pois.get()
            elif not self.remote_pois.empty():
                new_poi = self.remote_pois.get()

            if new_poi is None:
                time.sleep(1)
                continue

            if new_poi.loc_type == angr_comm_pb2.HumanPOI.FUNC_ADDR:
                func_name = self.mw.workspace.instance.cfg.functions[new_poi.code_location].name
                print("Sending update: func {}".format(func_name))
                add_poi_interest(func_name)
                fv = self.mw.workspace.views_by_category['functions'][0]
                fv.reload()
            else:
                print("Sending update: {:#10x}".format(new_poi.code_location))
                need_cg_update = cg.add_inst_interest(new_poi.code_location)
                add_poi_interest(new_poi.code_location)

            self.updatePOIs.emit(new_poi.code_location)

            if need_cg_update:
                cg.viewport().update()

            time.sleep(0.5)


def add_poi(addr, type='inst'):
    msg = angr_comm_pb2.HumanPOI()
    msg.tool = 'angr-management'
    msg.timestamp = int(time.time())
    msg.source = 'TEST_REMOTE_SOURCE'
    msg.file = 'TEST_BINARY_NAME'  # testlib/test_preload
    msg.code_location = addr
    if type == 'inst':
        msg.loc_type = angr_comm_pb2.HumanPOI.INST_ADDR
    elif type == 'func':
        msg.loc_type = angr_comm_pb2.HumanPOI.FUNC_ADDR

    UpdateWorker.local_pois.put(msg)





if __name__ == '__main__':
    fake_remote_actions = _make_fake_remote_actions()

