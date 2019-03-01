class HumanPOI:
	def __init__(self, addr):
		self.addr = addr
		self.tool = 'angr-management'


def select_func(addr):
	print("User selected function at 0x{:x}".format(addr))

def set_poi(addr):
	print("User is watching 0x{:x}".format(addr))

