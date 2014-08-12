import gdb
import traceback
import sys
import os
import inspect
from operator import attrgetter

cur_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
found = False
for p in sys.path:
	if p == cur_dir:
		found = True
		break
if not found:
	sys.path.insert(0, cur_dir)

import kstructs


class RbTree(gdb.Command):
	def __init__(self):
		gdb.Command.__init__(self, "rbtree", gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)
	
	def invoke(self, arg, from_tty):
		try:
			reload(kstructs)
			argv = gdb.string_to_argv(arg)
			if len(argv) == 1:
				root = kstructs.rb_root.ptr(long(int(argv[0], 16)))
				print root
			elif len(argv) == 3:
				root = kstructs.rb_root.ptr(long(int(argv[0], 16)))
				type_s = argv[1]
				field_s = argv[2]
				off = long(gdb.parse_and_eval('&((struct ' + type_s + ' *)0)->' + field_s))
				for n in root.enum_nodes():
					addr =  n.address - off
					cmd = 'p/x *(struct ' + type_s + ' *)' + kstructs.tohex64(addr) 
					gdb.write(cmd + '\n')
					gdb.execute(cmd)

			else:
				raise Exception("unknown args")

		except Exception as e:
			print "Exception=", str(e)
			traceback.print_exc()

RbTree()
