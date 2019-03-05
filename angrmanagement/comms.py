from queue import Queue
from PySide2 import QtCore

pois = Queue()

class HumanPOI:
	def __init__(self, addr):
		self.tool = 'angr-management'
		self.addr = addr

class HumanPOIAddr(HumanPOI):
	def __init__(self, addr):
		super(HumanPOIAddr, self).__init__(addr)


class HumanPOIFunc(HumanPOI):
	def __init__(self, func):
		super(HumanPOIFunc, self).__init__(func.addr)
		self.func = func


def set_poi_func(func):
	print("User selected function {} at 0x{:x}".format(func, func.addr))
	pois.put(HumanPOIFunc(func))

def set_poi_addr(addr):
	print("User selected address 0x{:x}".format(addr))
	pois.put(HumanPOIAddr(addr))

