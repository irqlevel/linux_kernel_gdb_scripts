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
			reload(kstructs)
			argv = gdb.string_to_argv(args)
			task_t = gdb.lookup_type('struct task_struct')
			thread_info_t = gdb.lookup_type('struct thread_info')
			if len(argv) == 0:
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
			elif len(argv) == 2:
				if argv[0] == "current":
					page_size = int(argv[1], 16)
					v = gdb.Value(long(gdb.parse_and_eval('$rsp')) & -page_size)
					th_info = v.cast(thread_info_t.pointer())
					task = kstructs.task_struct(th_info['task'].dereference())
					print task
				elif argv[0] == "task":
					v = gdb.Value(int(argv[1], 16))
					task_p = v.cast(task_t.pointer())
					task = kstructs.task_struct(task_p.dereference())
					print task
				elif argv[0] == "name":
					name = argv[1]
					list_off = gdb.parse_and_eval('&((struct task_struct *)0)->tasks')
					init = gdb.parse_and_eval("init_task")
					head = init['tasks']
					list_entry = head['next']
					while list_entry != head.address:
						v = gdb.Value(long(list_entry) - long(list_off))
						task_p = v.cast(task_t.pointer())
						task = kstructs.task_struct(task_p.dereference())
						if task.comm.find(name) != -1:
							print task, '\n'
						list_entry = list_entry['next']				
				else:
					raise Exception("Unknown option=" + argv[0])
			else:
				raise Exception("Invalid num args=" + len(argv))
		except Exception as e:
			print "Exception=", str(e)
			traceback.print_exc()

Tasks()
