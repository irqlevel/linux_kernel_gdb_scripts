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

class hlist_head():
	sz = 0
	@classmethod
	def size(cls):
		if cls.sz == 0:
			cls.sz = long(gdb.parse_and_eval("sizeof(struct hlist_head)"))
			#print cls.sz
		return cls.sz
	@classmethod
	def type_t(cls):
		return gdb.lookup_type('struct hlist_head')
	def __init__(self, v):
		self.v = v
	def first(self):
		if self.v['first'] != 0:
			return hlist_node(self.v['first'].dereference())
		return None
	def __str__(self):
		out = "hlist_head=" + str(self.v.address)
		#out+= " .first=" + str(self.first().v.address)
		return out
	def after(self):
		return hlist_head.ptr(long(self.v.address) + hlist_head.size())
	@classmethod
	def ptr(cls, addr):
		return cls(gdb.Value(addr).cast(cls.type_t().pointer()).dereference())

class hlist_node():
	def __init__(self, v):
		self.v = v
	def next(self):
		if self.v['next'] != 0:
			return hlist_node(self.v['next'])
		else:
			return None
	def __str__(self):
		out = "hlist_node=" + str(self.v.address)
		return out
class upid():
	pid_chain_off = 0
	sz = 0
	@classmethod
	def size(cls):
		if cls.sz == 0:
			cls.sz = long(gdb.parse_and_eval("sizeof(struct upid)"))
		return cls.sz

	@classmethod
	def get_pid_chain_off(cls):
		if cls.pid_chain_off == 0:
			cls.pid_chain_off = long(gdb.parse_and_eval('&((struct upid *)0)->pid_chain'))
		return cls.pid_chain_off

	def __init__(self, v):
		self.v = v
		self.nr = self.v['nr']
	@classmethod
	def type_t(cls):
		return gdb.lookup_type('struct upid')
	@classmethod
	def ptr(cls, addr):
		return cls(gdb.Value(addr).cast(cls.type_t().pointer()).dereference())
	@classmethod
	def from_pidhash_node(cls, node):
		return cls.ptr(long(node.v.address)-cls.get_pid_chain_off())
	def __str__(self):
		out = "upid=" + str(self.v.address) + " nr=" + str(self.nr)
		return out
	def get_pid_ns(self):
		if self.v['ns'] != 0:
			return pid_ns.ptr(long(self.v['ns']))
		else:
			return None

class pid_ns():
	def __init__(self, v):
		self.v = v
		self.level = long(self.v['level'])
		self.nr_hashed = long(self.v['nr_hashed'])
	@classmethod
	def type_t(cls):
		return gdb.lookup_type('struct pid_namespace')
	@classmethod
	def ptr(cls, addr):
		return cls(gdb.Value(addr).cast(cls.type_t().pointer()).dereference())
	def __str__(self):
		out = "pid_ns=" + str(self.v.address) + " level=" + str(self.level) + " nr_hashed=" + str(self.nr_hashed)
		return out


PIDTYPE_PID = 0
PIDTYPE_PGID = 1
PIDTYPE_SID = 2
PIDTYPE_MAX = 3

class pid_c():
	tasks_off = 0
	@classmethod
	def get_tasks_off(cls):
		if cls.tasks_off == 0:
			cls.tasks_off = long(gdb.parse_and_eval('&((struct pid *)0)->tasks'))
		return cls.tasks_off

	numbers_off = 0
	@classmethod
	def get_numbers_off(cls):
		if cls.numbers_off == 0:
			cls.numbers_off = long(gdb.parse_and_eval('&((struct pid *)0)->numbers'))
		return cls.numbers_off
	def __init__(self, v):
		self.v = v
		self.level = self.v['level']
		self.count = self.v['count']
		self.upids = []
		upid_addr = long(self.v.address) + pid_c.get_numbers_off()
		
		for i in xrange(self.level + 1):
			#print "i=", i
			up = upid.ptr(upid_addr)
			self.upids.append(up)
			upid_addr+= upid.size()

		tasks_addr = long(self.v.address) + pid_c.get_tasks_off()
		for i in xrange(PIDTYPE_MAX):
			head = hlist_head.ptr(tasks_addr)
			node = head.first()
			while node != None:
				#print node
				node = node.next()
			tasks_addr+= hlist_head.size()
	@classmethod
	def type_t(cls):
		return gdb.lookup_type('struct pid')
	@classmethod
	def ptr(cls, addr):
		return cls(gdb.Value(addr).cast(cls.type_t().pointer()).dereference())
	def __str__(self):
		out = "pid=" + str(self.v.address) + " level=" + str(self.level) + " count=" + str(self.count) + "\n"
		for up in self.upids:
			out+= "\t" + str(up) + "\n"
		out+= "\n"
		return out

	@classmethod
	def from_upid(cls, upid):
		pid_ns = upid.get_pid_ns()
		return cls.ptr(long(upid.v.address) - cls.get_numbers_off() - pid_ns.level*upid.size())


class Pids(gdb.Command):
	def __init__(self):
		gdb.Command.__init__(self, "pids", gdb.COMMAND_DATA, gdb.COMPLETE_SYMBOL, True)
	def invoke(self, args, from_tty):
		try:
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
					
				head = hlist_head.ptr(pid_hash.dereference().address)
				#print head
				pids_d = {}
				for i in xrange(pidhash_size):
					#print head, i
					node = head.first()
					while node != None:
						#print node
						up = upid.from_pidhash_node(node)
						#print #up, up.get_pid_ns(), pid_c.from_upid(up)
						pd = pid_c.from_upid(up)
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
