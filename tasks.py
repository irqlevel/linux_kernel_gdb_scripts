import gdb

class Tasks(gdb.Command):
	def __init__(self):
		gdb.Command.__init__(self, "tasks", gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)
	def invoke(self, arg, from_tty):
		try:
			task_t = gdb.lookup_type('struct task_struct')
			list_off = gdb.parse_and_eval('&((struct task_struct *)0)->tasks')
			init = gdb.parse_and_eval("init_task")
			head = init['tasks']
			list_entry = head['next']
			while list_entry != head.address:
				v = gdb.Value(long(list_entry) - long(list_off))
				task_p = v.cast(task_t.pointer())
				task = task_p.dereference()
				print task 
				list_entry = list_entry['next']
		except Exception as e:
			print "Exception=", str(e)
Tasks()
