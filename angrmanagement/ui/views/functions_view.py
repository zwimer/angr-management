from PySide2.QtWidgets import QVBoxLayout, QLabel
from PySide2.QtCore import QSize

from .view import BaseView
from ..widgets.qfunction_table import QFunctionTable


class FunctionsView(BaseView):
    def __init__(self, workspace, default_docking_position, *args, **kwargs):
        super(FunctionsView, self).__init__('functions', workspace, default_docking_position, *args, **kwargs)

        self.caption = 'Functions'
        self._function_table = None  # type:QFunctionTable
        self._status_label = None

        self._backcolor_callback = None
        self._func_select_callback = None
        self._init_widgets()

    @property
    def backcolor_callback(self):
        if self._function_table:
            return self._function_table.backcolor_callback

    @backcolor_callback.setter
    def backcolor_callback(self, v):
        self._backcolor_callback = v
        if self._function_table:
            self._function_table.backcolor_callback = v

    @property
    def func_select_callback(self):
        return self._func_select_callback

    @func_select_callback.setter
    def func_select_callback(self, v):
        self._func_select_callback = v

    def set_function_count(self, count):
        if self._status_label is not None:
            self._status_label.setText("%d functions" % count)

    #
    # Public methods
    #

    def reload(self):
        self._function_table.function_manager = self.workspace.instance.cfg.functions

    def sizeHint(self):
        return QSize(200, 0)

    #
    # Private methods
    #

    def _init_widgets(self):

        self._function_table = QFunctionTable(self, selection_callback=self._on_function_selected)
        self._function_table.backcolor_callback = self.backcolor_callback

        self._status_label = QLabel()

        vlayout = QVBoxLayout()
        vlayout.addWidget(self._function_table)
        vlayout.addWidget(self._status_label)

        self.setLayout(vlayout)

    def _on_function_selected(self, function):
        """
        A new function is on selection right now. Update the disassembly view that is currently at front.

        :param function:
        :return:
        """

        self.workspace.on_function_selected(function)
        if self.func_select_callback:
            self.func_select_callback(function)
