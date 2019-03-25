import time
import angr_comm_pb2
from queue import Queue
from collections import OrderedDict


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


class AddrDataDict:
    # TODO: Weight interest value based on user count

    def __init__(self, dict_of_dicts=None):
        if dict_of_dicts is not None:
            assert isinstance(dict_of_dicts, dict)
            self.import_dict_of_dicts(dict_of_dicts)
        else:
            self._data = OrderedDict()

    def __iter__(self):
        return self._data.__iter__()

    def __getitem__(self, k):
        return self._data.get(k, None)

    def __setitem__(self, k, v):
        del self[k]
        self._data[k] = v

    def __delitem__(self, k):
        if k in self:
            del self._data[k]

    def __contains__(self, k):
        return k in self._data

    def _quick_add_new(self, key, interest=0, tags=None):
        self[key] = AddrData(interest, tags)

    @property
    def data(self):
        return self._data

    def export_dict_of_dicts(self):
        o = OrderedDict()
        for ad in self._data:
            o[ad] = {}
            o[ad]['interest'] = self._data[ad].interest
            o[ad]['tags'] = self._data[ad].tags
        return o

    def import_dict_of_dicts(self, v):
        self._data = OrderedDict()
        for ad in v:
            self._data[ad] = AddrData(v['interest'], v['tags'])

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
            ret = sum(tv for k, tv in self[key].tags.items())
        return ret

    def get(self, addr):
        return self[addr]

    def copy(self):
        c = AddrDataDict()
        c._data = {k: v for k, v in self._data.items()}
        for _, ad in c._data.items():
            ad.tags = {k: v for k, v in ad.tags}
        return c


class ActivityTracker:
    local_acty = Queue()
    remote_acty = Queue()

    def __init__(self, source, tool_name, proj_name):
        self._tool_name = tool_name
        self._proj_name = proj_name
        self._source = source

        self._addr_data = None  # type:AddrDataDict

        self._is_running = False

    @property
    def addr_data(self):
        return self._addr_data

    @addr_data.setter
    def addr_data(self, v):
        self._addr_data = v

    def on_loop_begin(self):
        """
        Returns True or False. On True, execution simply
        continues. On False, the loop iterates.
        """
        return True

    def on_loop_end(self):
        """
        Returns True or False. On True, execution simply
        continues. On False, the loop terminates.
        """
        return True

    def on_user_poi(self, code_loc, tag):
        pass

    def on_user_acty(self, code_loc):
        pass

    def on_no_acty(self):
        """
        Returns True or False. On True, execution simply
        continues. On False, the loop terminates.
        """
        return True

    def get_function_name_at(self, addr):
        return None

    #
    # public methods
    #

    def add_user_acty(self, addr, addr_type=angr_comm_pb2.UserActy.INST_ADDR):
        pb_msg = angr_comm_pb2.UserActy()
        self.set_pb_default_props(addr, addr_type, pb_msg)
        self.local_acty.put(pb_msg)

    def add_user_poi(self, addr, addr_type=angr_comm_pb2.UserActy.INST_ADDR, tag='poi'):
        pb_msg = angr_comm_pb2.UserPOI()
        pb_msg.tag = tag
        self.set_pb_default_props(addr, addr_type, pb_msg.acty)
        self.local_acty.put(pb_msg)

    def _get_insn_backcolor_rgb(self, addr):
        if self.addr_data is not None:
            multiplier = 6  # HACK: must be larger with fewer people to make it more obvious
            # Tags are POIs and take precedence over interest, which is passive
            tv = self.addr_data.get_cumulative_tag_vals(addr)
            if tv:
                # starting at a light blue (0xd6d6ff) to dark blue (0x00133d)
                r = max(0xd6 - tv * multiplier, 0)
                g = max(0xd6 - tv * multiplier, 0x13)
                b = max(0xff - tv, 0x3d)
                return r, g, b

            interest = self.addr_data.get_interest(addr)
            if interest:
                # starting at a light green (0xd6ffdb) to dark green (0x003d13)
                r = max(0xd6 - interest * multiplier, 0)
                g = max(0xff - interest, 0x3d)
                b = max(0xd6 - interest * multiplier, 0x13)
                return r, g, b

        # Our highlight will be ignored if any of the values are -1
        return -1, -1, -1

    def set_pb_default_props(self, addr, addr_type, pb_acty_msg):
        pb_acty_msg.tool = self._tool_name
        pb_acty_msg.timestamp = int(time.time())
        pb_acty_msg.source = self._source
        pb_acty_msg.file = self._proj_name
        pb_acty_msg.code_location = addr
        pb_acty_msg.loc_type = addr_type

    def do_loop(self):
        self._is_running = True
        while True:
            if not self.on_loop_begin():
                continue

            new_msg = None
            # Handle our own updates before pulling in others'
            if not self.local_acty.empty():
                new_msg = self.local_acty.get()
            elif not self.remote_acty.empty():
                new_msg = self.remote_acty.get()

            if new_msg is None:
                if self.on_no_acty():
                    continue
                else:
                    break

            #
            # We only get here if there was a new message
            #

            if isinstance(new_msg, angr_comm_pb2.UserActy):
                code_loc = None
                if new_msg.loc_type == angr_comm_pb2.UserActy.FUNC_ADDR:
                    code_loc = self.get_function_name_at(new_msg.code_location)
                    print("Sending activity update: func {}".format(code_loc))
                else:
                    code_loc = new_msg.code_location
                    print("Sending activity update: {:#010x}".format(code_loc))
                self.on_user_acty(code_loc)
            elif isinstance(new_msg, angr_comm_pb2.UserPOI):
                print("Tagging POI (tag='{}') @ {:#010x}".format(new_msg.tag, new_msg.acty.code_location))
                self.on_user_poi(new_msg.acty.code_location, new_msg.tag)

            if not self.on_loop_end():
                break


######################### DEBUG #########################

__debug_tracker = ActivityTracker(source='debug_source', tool_name='debug_tool', proj_name='debug_proj')


def make_fake_remote_actions(rebase=True):
    fake_actions = []
    addrs = \
        [0x0040079a, 0x0040079b, 0x0040079e,  # first three addrs in main(), first should have 12
         0x00400636,  # not in first view (main), should still be added
         0x0040079a, 0x0040079a, 0x0040079a, 0x0040079a, 0x0040079a,  # repeats of above
         0x0040079a, 0x0040079a, 0x0040079a, 0x0040079a, 0x0040079a,  # repeats of above
         0x0040079a, 0x0040079b, 0x0040079e, 0x0040079e, 0x0040079e]  # repeats of above

    for addr in addrs:
        pb_msg = angr_comm_pb2.UserActy()
        if rebase is False:
            addr = addr - 0x00400000
        __debug_tracker.set_pb_default_props(addr, angr_comm_pb2.UserActy.INST_ADDR, pb_msg)
        fake_actions.append(pb_msg)

    # main function
    pb_msg = angr_comm_pb2.UserActy()
    addr = 0x0040079a
    if rebase is False:
        addr = addr - 0x00400000
    __debug_tracker.set_pb_default_props(addr, angr_comm_pb2.UserActy.FUNC_ADDR, pb_msg)
    fake_actions.append(pb_msg)
    return fake_actions


def write_actions(actions):
    pb_actylist = angr_comm_pb2.ActyList()
    pb_actylist.user_activity.extend(actions)
    pb_msg = pb_actylist.user_pois.add()
    pb_msg.tag = 'test_tag'
    __debug_tracker.set_pb_default_props(0x0040079b, angr_comm_pb2.UserActy.INST_ADDR, pb_msg.acty)

    with open('user_acty.msg', 'wb') as f:
        f.write(pb_actylist.SerializeToString())


def debug_write_fake_actions():
    write_actions(make_fake_remote_actions())
