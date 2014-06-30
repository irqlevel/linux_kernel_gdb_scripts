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

class Tasks(gdb.Command):
	def __init__(self):
		gdb.Command.__init__(self, "tasks", gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)
	def invoke(self, args, from_tty):
		try:
			task_t = gdb.lookup_type('struct task_struct')
			list_off = gdb.parse_and_eval('&((struct task_struct *)0)->tasks')
			init = gdb.parse_and_eval("init_task")
			head = init['tasks']
			list_entry = head['next']
			while list_entry != head.address:
				v = gdb.Value(long(list_entry) - long(list_off))
				task_p = v.cast(task_t.pointer())
				task = kstructs.task_struct(task_p.dereference())
				print task, '\n'
				list_entry = list_entry['next']
		except Exception as e:
			print "Exception=", str(e)
			traceback.print_exc()

Tasks()
