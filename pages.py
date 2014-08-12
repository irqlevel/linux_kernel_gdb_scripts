import gdb
import traceback
import sys
import os
import inspect

cur_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
found = False
for p in sys.path:
	if p == cur_dir:
		found = True
		break
if not found:
	sys.path.insert(0, cur_dir)

import kstructs

class Pages(gdb.Command):
	def __init__(self):
		gdb.Command.__init__(self, "pages", gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)
	def invoke(self, args, from_tty):
		try:
			reload(kstructs)
			argv = gdb.string_to_argv(args)
			if len(argv) == 2:
				if argv[0] == "addr":
					addr = int(argv[1], 16)
					p = kstructs.page.ptr(addr)
					print p
			else:
				raise Exception("Invalid num of args=" + str(len(argv)))
		except Exception as e:
			print "Exception=", str(e)
			traceback.print_exc()

Pages()
