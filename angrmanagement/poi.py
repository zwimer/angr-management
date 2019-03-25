from PySide2 import QtCore
from .chess import ActivityTracker, AddrDataDict, make_fake_remote_actions
import angr_comm_pb2
import time

#########################################################
from angr.knowledge_plugins.plugin import KnowledgeBasePlugin


class PoiPlugin(KnowledgeBasePlugin, AddrDataDict):
    def __init__(self, kb, dict_of_dicts=None):
        AddrDataDict.__init__(self, dict_of_dicts=dict_of_dicts)
        KnowledgeBasePlugin.__init__(self)
        import angr.knowledge_base
        self._kb = kb  # type: angr.knowledge_base.KnowledgeBase

    def copy(self):
        c = AddrDataDict.copy()
        c._kb = self._kb


KnowledgeBasePlugin.register_default('pois', PoiPlugin)
#########################################################


class UpdateWorker(QtCore.QThread, ActivityTracker):
    def __init__(self, main_window):
        QtCore.QThread.__init__(self)
        ActivityTracker.__init__(self, source='my_user_name', tool_name='angr-management', proj_name='test_proj')
        self.mw = main_window
        self.poi_plugin = None
        # HACK: Should add a get_ctx_addr()
        self.ctx_menu = None
        ######################### DEBUG #########################
        remotes = make_fake_remote_actions()
        for r in remotes:
            self.remote_acty.put(r)
        #########################################################

    def on_loop_begin(self):
        #
        # Wait for the CFG analysis to complete and then
        # get our plugin and set callbacks
        #
        while self.poi_plugin is None:
            if self.mw.workspace.instance.cfg is not None:
                self.poi_plugin = self.mw.workspace.instance.cfg.kb.get_plugin('pois')
                self.mw.workspace.set_function_select_callback(self.on_function_select)
                self.mw.workspace.set_function_backcolor_callback(self.get_function_backcolor_rgb)
                self.mw.workspace.set_insn_backcolor_callback(self.get_insn_backcolor_rgb)
                self.mw.workspace.set_insn_select_callback(self.on_insn_select)
                self.mw.workspace.set_comment_callback(self.on_set_comment)
                self.mw.workspace.set_label_rename_callback(self.on_label_rename)
                self.ctx_menu = self.mw.workspace.views_by_category['disassembly'][0].add_disasm_insn_ctx_menu_entry('Tag &POI', self.on_ctx_menu_tag_poi)
            else:
                time.sleep(1)  # wait a second for analysis to finish

        return True

    def on_loop_end(self):
        self.mw.workspace.views_by_category['disassembly'][0].current_graph.viewport().update()
        time.sleep(0.25)
        return True

    def on_user_poi(self, code_loc, tag):
        self.poi_plugin.add_tag(code_loc, tag, 1)

    def on_user_acty(self, code_loc):
        self.poi_plugin.add_interest(code_loc)

    def on_no_acty(self):
        time.sleep(1)
        return True

    def get_function_name_at(self, addr):
        return self.mw.workspace.instance.cfg.functions[addr].name

    def on_label_rename(self, addr, new_name):
        print("Adding label name: {:#010x}='{}'".format(addr, new_name))
        self.add_user_poi(addr, tag="label:{}".format(new_name))

    def on_insn_select(self, addr):
        self.add_user_acty(addr)

    def on_set_comment(self, addr):
        print("Comment set on {:#010x}".format(addr))
        self.add_user_acty(addr)

    def on_function_select(self, func):
        self.add_user_acty(func.addr, addr_type=angr_comm_pb2.UserActy.FUNC_ADDR)

    def get_function_backcolor_rgb(self, func):
        if func.name is None or func.name is '':
            return 255, 255, 255

        # HACK for a bug. See: https://github.com/angr/cle/pull/175. Won't need None check when merged.
        if func.binary._entry is not None and func.addr == func.binary.entry:
            return 0xe5, 0xfb, 0xff  # light blue
        elif self.poi_plugin:
            interest = self.poi_plugin.get_interest(func.name)
            interest += self.poi_plugin.get_cumulative_tag_vals(func.name)
            if interest:
                r = max(0xd6 - 2 * interest, 0)
                g = max(0xff - interest, 0x3d)
                b = max(0xd6 - 2 * interest, 0x13)
                return r, g, b

        return 255, 255, 255

    def get_insn_backcolor_rgb(self, addr):
        multiplier = 6  # HACK: must be larger with fewer people to make it more obvious
        # Tags are POIs and take precedence over interest, which is passive
        tv = self.poi_plugin.get_cumulative_tag_vals(addr)
        if tv:
            r = max(0xd6 - tv * multiplier, 0)
            g = max(0xd6 - tv * multiplier, 0x13)
            b = max(0xff - tv, 0x3d)
            return r, g, b

        interest = self.poi_plugin.get_interest(addr)
        if interest:
            # starting at a light green (0xd6ffdb) to dark green (0x003d13)
            r = max(0xd6 - interest * multiplier, 0)
            g = max(0xff - interest, 0x3d)
            b = max(0xd6 - interest * multiplier, 0x13)
            return r, g, b

        # Our highlight will be ignored if any of the values are -1
        return -1, -1, -1

    def on_ctx_menu_tag_poi(self):
        addr = self.ctx_menu.insn_addr
        self.add_user_poi(addr, addr_type=angr_comm_pb2.UserActy.INST_ADDR)

    def run(self):
        self.do_loop()
