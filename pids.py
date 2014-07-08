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

class Pids(gdb.Command):
	def __init__(self):
		gdb.Command.__init__(self, "pids", gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)
	def invoke(self, args, from_tty):
		try:
			reload(kstructs)
			argv = gdb.string_to_argv(args)
			upid_t = gdb.lookup_type('struct upid')
			pid_t = gdb.lookup_type('struct pid')
			pid_ns_t = gdb.lookup_type('struct pid_namespace')
			hlist_node_t = gdb.lookup_type('struct hlist_node')

			if len(argv) == 0:
				pid_hash = gdb.parse_and_eval("pid_hash")
				pidhash_shift = gdb.parse_and_eval("pidhash_shift")
				pidhash_size = 1 << pidhash_shift
				#print hlist_head.size()
				#print long(pid_hash), long(pidhash_shift), long(pidhash_size)
					
				head = kstructs.hlist_head.ptr(pid_hash.dereference().address)
				#print head
				pids_d = {}
				for i in xrange(pidhash_size):
					#print head, i
					node = head.first()
					while node != None:
						#print node
						up = kstructs.upid.from_pidhash_node(node)
						#print #up, up.get_pid_ns(), pid_c.from_upid(up)
						pd = kstructs.pid_c.from_upid(up)
						pids_d[long(pd.v.address)] = pd
						node = node.next()
					#print head
					head = head.after()
				for k in pids_d:
					print pids_d[k]
			elif len(argv) == 2:
				if argv[0] == "pid":
					pid = int(argv[1], 16)
					raise Exception("Unknown option=" + argv[0])
			else:
				raise Exception("Invalid num args=" + len(argv))
		except Exception as e:
			print "Exception=", str(e)
			traceback.print_exc()

Pids()
