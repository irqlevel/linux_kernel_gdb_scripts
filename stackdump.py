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

class Stackdump(gdb.Command):
	def __init__(self):
		gdb.Command.__init__(self, "stackdump", gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)
	
	def invoke(self, args, from_tty):
		try:
			reload(kstructs)
			argv = gdb.string_to_argv(args)
			if len(argv) == 2:
				sbase = long(argv[0], 16)
				limit = long(argv[1], 16)
				ptr_size = gdb.parse_and_eval("sizeof(void *)")
				curr = sbase
				while curr < (sbase + limit):
					v = kstructs.ptr_ptr.ptr(curr)
					pc = long(v.v)
					out = ""
					out = kstructs.tohex64(curr) + " -> " + kstructs.tohex64(pc)
					if pc and ((pc < sbase) or (pc >= sbase + limit)):
						pc_s = kstructs.tohex64(pc)
						rs = gdb.find_pc_line(pc)
						if rs.symtab and rs.line:
							b = gdb.block_for_pc(pc)
							out+= " " + str(b.function) + "():"  + " " + str(rs.symtab) + ":" + str(rs.line)
					print out
					curr+= ptr_size
			else:
				raise Exception("Invalid num args=" + len(argv))
		except Exception as e:
			print "Exception=", str(e)
			traceback.print_exc()
Stackdump()
