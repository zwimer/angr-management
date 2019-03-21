from PySide2 import QtCore
from queue import Queue
import time
import angr_comm_pb2

#########################################################
from angr.knowledge_plugins.plugin import KnowledgeBasePlugin


class AddrData:
    # TODO: track local/remote interest & tags separately
    def __init__(self, interest=0, tags=None):
        self._interest = interest
        self._tags = tags if isinstance(tags, dict) else dict()

    @property
    def interest(self):
        if not isinstance(self._interest, int):
            self._interest = 0
        return self._interest

    @interest.setter
    def interest(self, v):
        if isinstance(v, int):
            self._interest = v

    @property
    def tags(self):
        if not isinstance(self._tags, dict):
            self._tags = {}
        return self._tags

    def add_tag_value(self, tag, addend=1):
        """
        A tag is a hashable type, usually a string, and its value is
        how many times that tag has been set.
        """
        if tag not in self.tags:
            self._tags[tag] = addend
        else:
            self._tags[tag] += addend


class POIs(KnowledgeBasePlugin):
    # TODO: Save POI objects rather than just interest val
    # TODO: With HumanPOIFunc, use addr so names don't matter
    # TODO: Track unique members so interest count is weighted (2 people = bigger changes in color, etc)

    def __init__(self, kb):
        self._kb = kb
        self._addr_data = {}

    def __iter__(self):
        return self._addr_data.__iter__()

    def __getitem__(self, k):
        return self._addr_data.get(k, None)

    def __setitem__(self, k, v):
        del self[k]
        self._addr_data[k] = v

    def __delitem__(self, k):
        if k in self:
            del self._addr_data[k]

    def __contains__(self, k):
        return k in self._addr_data

    def _quick_add_new(self, key, interest=0, tags=None):
        self[key] = AddrData(interest, tags)

    def add_interest(self, key, addend=1):
        if self[key]:
            self[key].interest += addend
        else:
            self._quick_add_new(key, interest=addend)

    def get_interest(self, key):
        ret = 0
        if self[key]:
            ret = self[key].interest
        return ret

    def add_tag(self, key, tag, tag_val=1):
        if self[key]:
            self[key].add_tag_value(tag, tag_val)
        else:
            self._quick_add_new(key, interest=0, tags={tag: tag_val})

    def get_tag_count(self, key):
        ret = 0
        if self[key]:
            ret = len(self[key].tags)
        return ret

    def get_cumulative_tag_vals(self, key):
        ret = 0
        if self[key]:
            ret = sum(tv for k,tv in self[key].tags.items())
        return ret

    def get(self, addr):
        return self[addr]

    def copy(self):
        c = POIs(self._kb)
        c._addr_data = {k: v for k, v in self._addr_data.items()}
        for _, ad in c._addr_data.items():
            ad.tags = {k: v for k, v in ad.tags}
        return c


KnowledgeBasePlugin.register_default('pois', POIs)

#########################################################


def _set_pb_default_props(addr, type, pb_acty_msg):
    pb_acty_msg.tool = 'angr-management'
    pb_acty_msg.timestamp = int(time.time())
    pb_acty_msg.source = 'TEST_REMOTE_SOURCE'
    pb_acty_msg.file = 'auth_linux_x64'
    pb_acty_msg.code_location = addr
    if type == 'inst':
        pb_acty_msg.loc_type = angr_comm_pb2.UserActy.INST_ADDR
    elif type == 'func':
        pb_acty_msg.loc_type = angr_comm_pb2.UserActy.FUNC_ADDR


######################### DEBUG #########################
def _make_fake_remote_actions():
    import time
    fake_actions = []
    addrs = \
        [0x0040079a, 0x0040079b, 0x0040079e,  # first three addrs in main(), first should have 12
         0x00400630,  # not in first view, should error in add_inst_interest()
         0x0040079a, 0x0040079a, 0x0040079a, 0x0040079a, 0x0040079a,  # repeats of above
         0x0040079a, 0x0040079a, 0x0040079a, 0x0040079a, 0x0040079a,  # repeats of above
         0x0040079a, 0x0040079b, 0x0040079e, 0x0040079e, 0x0040079e]  # repeats of above
    for addr in addrs:
        pb_msg = angr_comm_pb2.UserActy()
        _set_pb_default_props(addr, 'inst', pb_msg)
        fake_actions.append(pb_msg)

    # main function
    pb_msg = angr_comm_pb2.UserActy()
    _set_pb_default_props(0x0040079a, 'func', pb_msg)
    fake_actions.append(pb_msg)
    return fake_actions


def _write_actions(actions):
    pb_actylist = angr_comm_pb2.ActyList()
    pb_actylist.user_activity.extend(actions)

    pb_msg = pb_actylist.user_pois.add()
    pb_msg.tag = 'test_tag'
    _set_pb_default_props(0x0040079b, 'inst', pb_msg.acty)

    with open('user_acty.msg', 'wb') as f:
        f.write(pb_actylist.SerializeToString())


#########################################################

poi_plugin = None


def on_label_rename(addr, new_name):
    print("Adding label name: {:#010x}='{}'".format(addr, new_name))
    add_user_poi(addr, tag="label:{}".format(new_name))


def on_insn_select(addr):
    track_user_acty(addr)


def on_function_select(func):
    track_user_acty(func.addr, type='func')


def get_function_backcolor_rgb(func):
    if func.name is None or func.name is '':
        return 255, 255, 255

    # HACK for a bug. See: https://github.com/angr/cle/pull/175. Won't need None check when merged.
    if func.binary._entry is not None and func.addr == func.binary.entry:
        return 0xe5, 0xfb, 0xff     # light blue
    elif poi_plugin:
        interest = poi_plugin.get_interest(func.name)
        interest += poi_plugin.get_cumulative_tag_vals(func.name)
        if interest:
            r = max(0xd6 - 2 * interest, 0)
            g = max(0xff - interest, 0x3d)
            b = max(0xd6 - 2 * interest, 0x13)
            return r, g, b

    return 255, 255, 255


def get_insn_backcolor_rgb(addr):
    multiplier = 6  # HACK: must be larger with fewer people to make it more obvious
    # Tags are POIs and take precedence over interest, which is passive
    tv = poi_plugin.get_cumulative_tag_vals(addr)
    if tv:
        r = max(0xd6 - tv * multiplier, 0)
        g = max(0xd6 - tv * multiplier, 0x13)
        b = max(0xff - tv, 0x3d)
        return r, g, b

    interest = poi_plugin.get_interest(addr)
    if interest:
        # starting at a light green (0xd6ffdb) to dark green (0x003d13)
        r = max(0xd6 - interest * multiplier, 0)
        g = max(0xff - interest, 0x3d)
        b = max(0xd6 - interest * multiplier, 0x13)
        return r, g, b

    # Our highlight will be ignored if any of the values are -1
    return -1, -1, -1


class UpdateWorker(QtCore.QThread):
    updatePOIs = QtCore.Signal((int,), (str,))

    # Note that these are class attributes, not instance. There's no
    # reason to have several queues floating around... I think.
    local_acty = Queue()
    remote_acty = Queue()

    def __init__(self, main_window):
        QtCore.QThread.__init__(self)
        self.mw = main_window

        ######################### DEBUG #########################
        remotes = _make_fake_remote_actions()
        for r in remotes:
            self.remote_acty.put(r)
        #########################################################

    def run(self):
        # We need to get the POI plugin. If it's not there, it's because
        # the user hasn't loaded a binary or the project hasn't done its
        # analysis yet.
        global poi_plugin

        while poi_plugin is None:
            if self.mw.workspace.instance.cfg is not None:
                poi_plugin = self.mw.workspace.instance.cfg.kb.get_plugin('pois')
                self.mw.workspace.set_function_select_callback(on_function_select)
                self.mw.workspace.set_function_backcolor_callback(get_function_backcolor_rgb)
                self.mw.workspace.set_insn_backcolor_callback(get_insn_backcolor_rgb)
                self.mw.workspace.set_insn_select_callback(on_insn_select)
                self.mw.workspace.set_label_rename_callback(on_label_rename)
            else:
                time.sleep(1)  # wait a second for analysis to finish

        while True:
            # Get the current view (func graph vs linear)
            cg = self.mw.workspace.views_by_category['disassembly'][0].current_graph

            new_msg = None
            # Handle our own updates before pulling in others'
            if not self.local_acty.empty():
                new_msg = self.local_acty.get()
            elif not self.remote_acty.empty():
                new_msg = self.remote_acty.get()

            if new_msg is None:
                time.sleep(1)
                continue

            #
            # We only get here if there was a new message
            #
            pp_key = None
            if isinstance(new_msg, angr_comm_pb2.UserActy):
                if new_msg.loc_type == angr_comm_pb2.UserActy.FUNC_ADDR:
                    pp_key = self.mw.workspace.instance.cfg.functions[new_msg.code_location].name
                    print("Sending update: func {}".format(pp_key))
                    poi_plugin.add_interest(pp_key)
                else:
                    pp_key = new_msg.code_location
                    print("Sending update: {:#010x}".format(new_msg.code_location))
                    poi_plugin.add_interest(pp_key)
            elif isinstance(new_msg, angr_comm_pb2.UserPOI):
                print("Tagging POI (tag='{}') @ {:#010x}".format(new_msg.tag, new_msg.acty.code_location))
                pp_key = new_msg.acty.code_location
                poi_plugin.add_tag(pp_key, new_msg.tag, 1)

            self.updatePOIs[type(pp_key)].emit(pp_key)
            cg.viewport().update()
            time.sleep(0.25)


def track_user_acty(addr, type='inst'):
    pb_msg = angr_comm_pb2.UserActy()
    _set_pb_default_props(addr, type, pb_msg)
    UpdateWorker.local_acty.put(pb_msg)


def add_user_poi(addr, type='inst', tag=None):
    pb_msg = angr_comm_pb2.UserPOI()
    pb_msg.tag = tag
    _set_pb_default_props(addr, type, pb_msg.acty)
    UpdateWorker.local_acty.put(pb_msg)


if __name__ == '__main__':
    _write_actions(_make_fake_remote_actions())
