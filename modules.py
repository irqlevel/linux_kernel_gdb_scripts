import gdb

class Modules(gdb.Command):
	def __init__(self):
		gdb.Command.__init__(self, "modules", gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)
	def invoke(self, arg, from_tty):
		try:
			m_type = gdb.lookup_type('struct module')
			list_off = gdb.parse_and_eval('&((struct module *)0)->list')
			head = gdb.parse_and_eval("modules")
			list_entry = head['next']
			while list_entry != head.address:
				v = gdb.Value(long(list_entry) - long(list_off))
				mod_p = v.cast(m_type.pointer())
				mod = mod_p.dereference()
				print 'name=' + str(mod['name']) + ' addr=' + str(mod['module_core'])
				list_entry = list_entry['next']
		except Exception as e:
			print "Exception=", str(e)
Modules()
