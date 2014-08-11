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

class Files(gdb.Command):
	def __init__(self):
		gdb.Command.__init__(self, "files", gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)
	def invoke(self, args, from_tty):
		try:
			reload(kstructs)
			argv = gdb.string_to_argv(args)
			if len(argv) == 2:
				if argv[0] == "file":
					addr = int(argv[1], 16)
					f = kstructs.file.ptr(addr)
					print f
				elif argv[0] == "dentry":
					addr = int(argv[1], 16)
					dentry = kstructs.dentry.ptr(addr)
					print dentry
				else:
					raise Exception("Unknown option=" + argv[0])
			else:
				raise Exception("Invalid num args=" + len(argv))
		except Exception as e:
			print "Exception=", str(e)
			traceback.print_exc()

Files()
