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

class Modules(gdb.Command):
	def __init__(self):
		gdb.Command.__init__(self, "modules", gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)
	def invoke(self, arg, from_tty):
		try:
			reload(kstructs)
			m_type = gdb.lookup_type('struct module')
			list_off = gdb.parse_and_eval('&((struct module *)0)->list')
			head = gdb.parse_and_eval("modules")
			list_entry = head['next']
			while list_entry != head.address:
				v = gdb.Value(long(list_entry) - long(list_off))
				mod_p = v.cast(m_type.pointer())
				mod = kstructs.module(mod_p.dereference())
				print mod, '\n'
				list_entry = list_entry['next']
		except Exception as e:
			print "Exception=", str(e)
			traceback.print_exc()

Modules()
