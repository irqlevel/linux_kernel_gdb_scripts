import gdb
import traceback
import inspect
import sys
import os



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
	@classmethod
	def type_t(cls):
		return gdb.lookup_type('struct hlist_node')

	@classmethod
	def ptr(cls, addr):
		return cls(gdb.Value(addr).cast(cls.type_t().pointer()).dereference())

	def next(self):
		if self.v['next'] != 0:
			return hlist_node.ptr(long(self.v['next']))
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

class pid_link():
	def __init__(self, v):
		self.v = v
	sz = 0
	@classmethod
	def size(cls):
		if cls.sz == 0:
			cls.sz = long(gdb.parse_and_eval("sizeof(struct pid_link)"))
		return cls.sz

	@classmethod
	def type_t(cls):
		return gdb.lookup_type('struct pid_link')
	@classmethod
	def ptr(cls, addr):
		return cls(gdb.Value(addr).cast(cls.type_t().pointer()).dereference())
	def __str__(self):
		out = "pid_link=" + str(self.v.address)
		return out

PIDTYPE_PID = 0
PIDTYPE_PGID = 1
PIDTYPE_SID = 2
PIDTYPE_MAX = 3

PIDTYPES = {PIDTYPE_PID : "PID", PIDTYPE_PGID : "PGID", PIDTYPE_SID : "SID"}

class atomic_t():
	def __init__(self, v):
		self.v = v
		self.counter = long(self.v['counter'])
	def __str__(self):
		out = "atomic_t=" + str(self.v.address) + " counter=" + str(self.counter)
		return out

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
		self.count = atomic_t(self.v['count'])

	def get_uids(self):
		self.upids = []
		upid_addr = long(self.v.address) + pid_c.get_numbers_off()
		
		for i in xrange(self.level + 1):
			#print "i=", i
			up = upid.ptr(upid_addr)
			self.upids.append(up)
			upid_addr+= upid.size()
	
	def get_tasks(self):
		self.tasks = {PIDTYPE_PID : [], PIDTYPE_PGID : [], PIDTYPE_SID : []}
		tasks_addr = long(self.v.address) + pid_c.get_tasks_off()
		for i in xrange(PIDTYPE_MAX):
			head = hlist_head.ptr(tasks_addr)
			#print head
			node = head.first()
			while node != None:
				#print node
				pl = pid_link.ptr(long(node.v.address))
				self.tasks[i].append(task_struct.from_pid_link(pl, i))
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
		self.get_uids()
		out+= "\t upids:\n"
		for up in self.upids:
			out+= "\t\t" + str(up) + "\n"
		out+= "\n"
		self.get_tasks()
		out+= "\t tasks:\n"
		for i in xrange(PIDTYPE_MAX):
			out+= "\t\t" + PIDTYPES[i] + ":\n"
			for t in self.tasks[i]:
				out+= "\t\t\t" + t.to_str() + "\n"
		out+= "\n"
		return out

	@classmethod
	def from_upid(cls, upid):
		pid_ns = upid.get_pid_ns()
		return cls.ptr(long(upid.v.address) - cls.get_numbers_off() - pid_ns.level*upid.size())


class list_head():
	sz = 0
	@classmethod
	def size(cls):
		if cls.sz == 0:
			cls.sz = long(gdb.parse_and_eval("sizeof(struct list_head)"))
		return cls.sz
	@classmethod
	def type_t(cls):
		return gdb.lookup_type('struct list_head')
	def __init__(self, v):
		self.v = v
	@classmethod
	def ptr(cls, addr):
		return cls(gdb.Value(addr).cast(cls.type_t().pointer()).dereference())
	def __str__(self):
		out = "list_head=" + str(self.v.address)
		return out
	def next(self):
		if self.v['next'] != 0:
			return list_head(self.v['next'].dereference())
		return None
	def prev(self):
		if self.v['prev'] != 0:
			return list_head(self.v['prev'].dereference())
		return None
	@classmethod
	def list(cls, head_addr, trace = False):
		if trace:
			print "list_head=" +  hex(head_addr)
		head = cls.ptr(head_addr)
		entry = head.next()
		l = []
		while entry.address() != head.address():
			l.append(entry)
			if trace:
				print entry
			entry = entry.next()
		return l
	def address(self):
		return long(self.v.address)
	def address_s(self):
		return str(self.v.address)

class task_struct():
	children_off = 0
	sibling_off = 0
	sz = 0
	pids_off = 0
	@classmethod
	def get_pids_off(cls):
		if cls.pids_off == 0:
			cls.pids_off = long(gdb.parse_and_eval("&((struct task_struct *)0)->pids"))
		return cls.pids_off
	
	@classmethod
	def size(cls):
		if cls.sz == 0:
			cls.sz = long(gdb.parse_and_eval("sizeof(struct task_struct)"))
		return cls.sz
	
	@classmethod
	def ptr(cls, addr):
		return cls(gdb.Value(addr).cast(cls.type_t().pointer()).dereference())

	@classmethod
	def get_children_off(cls):
		if cls.children_off == 0:
			cls.children_off = long(gdb.parse_and_eval('&((struct task_struct *)0)->children'))
		return cls.children_off

	@classmethod
	def get_sibling_off(cls):
		if cls.sibling_off == 0:
			cls.sibling_off = long(gdb.parse_and_eval('&((struct task_struct *)0)->sibling'))
		return cls.sibling_off

	@classmethod
	def type_t(cls):
		return gdb.lookup_type('struct task_struct')

	@classmethod
	def from_pid_link(cls, pid_link, i):
		return cls.ptr(long(pid_link.v.address) - i*pid_link.size() - cls.get_pids_off())

	def address(self):
		return long(self.v.address)
	def address_s(self):
		return str(self.v.address)
	def __init__(self, v):
		self.v = v
		#print 'task=', self.v.address
		self.pid = v['pid']
		self.state = v['state']
		self.exit_state = v['exit_state']
		self.flags = v['flags']
		self.stack = v['stack']
		if v['comm']:
			self.comm = v['comm'].string()
		else:
			self.comm = ''
		self.mm = None
		self.childs = []

	def get_mm(self):
		if self.v['mm'] != 0:
			self.mm = mm_struct(self.v['mm'].dereference())
		else:
			self.mm = None
		return self.mm

	def get_childs(self):
		#print hex(self.address()), hex(task_struct.get_children_off())
		ha = self.address() + task_struct.get_children_off()
		#print hex(ha)
		l = list_head.list(ha)
		off = task_struct.get_children_off()
		for e in l:
			t = task_struct.ptr(e.address()-task_struct.get_sibling_off())
			self.childs.append(t)
		return self.childs
			
	def to_str(self, mm = False, stack = False, childs = False, flags = False, state = False, exit_state = False, comm = False):
		out = 'task=' + self.address_s() + ' pid=' + str(self.pid)
		if flags:
			out+= ' flags=' + hex(long(self.flags))
		if state:
			out+= ' state=' + str(self.state) 
		if stack:
			out += ' stack=' + str(self.stack) + '\n'
		if comm:
			out += ' comm=' + self.comm + '\n'
		if mm:
			self.get_mm()
			out += '\n'
			out += ' ' + str(self.mm)

		if childs:
			self.get_childs()
			out+= '\n\tchilds:\n'
			for t in self.childs:
				out += '\t\t' + t.to_str(flags = True, comm = True) + '\n'
		return out

	def __str__(self):
		return self.to_str(mm=True, stack=True, childs=True, flags=True, state=True, exit_state=True, comm=True)

class mm_struct():
	def __init__(self, v):
		self.v = v
		#print 'mm=', self.v.address
		if self.v['exe_file'] != 0:
			self.exe_file = file(self.v['exe_file'].dereference())	
		else:
			self.exe_file = None
	def __str__(self):
		out = 'mm=' + str(self.v.address)
		if self.exe_file != None:
			out+= '\n'
			out+= '		' + str(self.exe_file)
		return out

class dentry():
	sz = 0
	@classmethod
	def size(cls):
		if cls.sz == 0:
			cls.sz = long(gdb.parse_and_eval("sizeof(struct dentry)"))
		return cls.sz
	@classmethod
	def type_t(cls):
		return gdb.lookup_type('struct dentry')
	@classmethod
	def ptr(cls, addr):
		return cls(gdb.Value(addr).cast(cls.type_t().pointer()).dereference())

	def __init__(self, v):
		self.v = v
		self.d_name = self.v['d_name']['name'].string()

		#print long(v.address), long(v['d_parent'])
		if long(self.v['d_parent']) == 0:
			self.d_parent = None
		elif long(self.v['d_parent']) == long(self.v.address):
			self.d_parent = None
		else:
			self.d_parent = dentry(self.v['d_parent'].dereference())
		self.full_path = self.query_full_path()
	def query_full_path(self):
		if self.d_parent != None:
			path = self.d_parent.query_full_path() + '/' + self.d_name
		else:
			path = self.d_name
		return path
	def __str__(self):
		out = "dentry=" + str(self.v.address) + " " + self.query_full_path()
		return out

class file():
	sz = 0
	@classmethod
	def size(cls):
		if cls.sz == 0:
			cls.sz = long(gdb.parse_and_eval("sizeof(struct file)"))
		return cls.sz
	@classmethod
	def type_t(cls):
		return gdb.lookup_type('struct file')
	@classmethod
	def ptr(cls, addr):
		return cls(gdb.Value(addr).cast(cls.type_t().pointer()).dereference())
	def __init__(self, v):
		self.v = v
		#print 'file=', self.v.address
		self.f_path = path(self.v['f_path'])
	def query_path(self):
		return self.f_path.query_path()
	def __str__(self):
		out = 'file=' + str(self.v.address) + " " + self.query_path()
		return out

class path():
	def __init__(self, v):
		self.v = v
		self.mnt = vfsmount(self.v['mnt'].dereference())
		self.dentry = dentry(self.v['dentry'].dereference())
	def query_path(self):
		return self.mnt.mnt_root.query_full_path() + self.dentry.query_full_path()
	def __str__(self):
		out= 'path=' + str(self.v.address) + " " + self.query_path()
		return out

def tohex(val, nbits):
	return hex(long((long(val) + (1 << nbits)) % (1 << nbits))).rstrip('L')

def tohex64(val):
	try:
		return tohex(val, 64)
	except Exception as e:
		print str(e), val
		raise

def int_addr(val):
	return int(tohex64(val), 16)

class module_sect_attr():
	sz = 0
	def __init__(self, v):
		self.v = v
		self.name = self.v['name'].string()
		self.address = self.v['address']
	@classmethod
	def size(cls):
		if cls.sz == 0:
			cls.sz = long(gdb.parse_and_eval("sizeof(struct module_sect_attr)"))
		return cls.sz
	@classmethod
	def ptr(cls, addr):
		return cls(gdb.Value(addr).cast(cls.type_t().pointer()).dereference())
	@classmethod
	def type_t(cls):
		return gdb.lookup_type('struct module_sect_attr')
	def __str__(self):
		out = "sec_attr name=" + self.name + " addr=" + tohex64(self.address)
		return out

class ptr_ptr():
	def __init__(self, v):
		self.v = v
	c_type = None
	@classmethod
	def type_t(cls):
		if cls.c_type == None:
			cls.c_type = gdb.lookup_type('long')
		return cls.c_type
	@classmethod
	def ptr(cls, addr):
		return cls(gdb.Value(addr).cast(cls.type_t().pointer()).dereference())

class module_sect_attrs():
	def __init__(self, v):
		self.v = v
		self.nsections = int(self.v['nsections'])
		sec_attr_addr = long(self.v.address) + module_sect_attrs.get_attrs_off()
		self.sec_attrs = []
		for i in xrange(self.nsections):
			sec_attr = module_sect_attr.ptr(sec_attr_addr)
			sec_attr_addr+= module_sect_attr.size()
			self.sec_attrs.append(sec_attr)
	attrs_off = 0
	@classmethod
	def get_attrs_off(cls):
		if cls.attrs_off == 0:
			cls.attrs_off = long(gdb.parse_and_eval("&((struct module_sect_attrs *)0)->attrs"))
		return cls.attrs_off
	
	@classmethod
	def ptr(cls, addr):
		return cls(gdb.Value(addr).cast(cls.type_t().pointer()).dereference())
	@classmethod
	def type_t(cls):
		return gdb.lookup_type('struct module_sect_attrs')
	def __str__(self):
		out = 'sec_attrs=' + str(self.v.address) + '\n'
		for sec_attr in self.sec_attrs:
			out+= " \t" + str(sec_attr) + '\n'
		return out

class module():
	def __init__(self, v):
		self.v = v
		self.name = self.v['name'].string()
		self.args = self.v['args'].string()
		self.module_core = self.v['module_core']
		self.core_size = self.v['core_size']
		self.core_text_size = self.v['core_text_size']
		self.base_addr = long(self.module_core)
		self.size = long(self.core_size)
		self.sect_attrs = None
	def sections(self):
		self.sect_attrs = module_sect_attrs.ptr(long(self.v['sect_attrs'].dereference().address))
		
	def __str__(self):
		out = 'module=' + str(self.v.address) + ' name=' + self.name + ' module_core=' + str(self.module_core) 
		out+= ' core_size=' + str(self.core_size) + ' core_text_size=' + str(self.core_text_size) + '\n'
		if self.sect_attrs != None:
			out+= str(self.sect_attrs)
		return out

class vfsmount():
	def __init__(self, v):
		self.v = v
		#print 'vfs_mount=', self.v.address
		self.mnt_root = dentry(self.v['mnt_root'].dereference())

class rb_node():
	def __init__(self, v):
		self.v = v
		self.rb_parent_color = self.v['rb_parent_color']
		self.address = long(self.v.address)

	def rb_right(self):
		if self.v['rb_right']:
			return rb_node(self.v['rb_right'].dereference())
		return None

	def rb_left(self):
		if self.v['rb_left']:
			return rb_node(self.v['rb_left'].dereference())
		return None

	@classmethod
	def ptr(cls, addr):
		return cls(gdb.Value(addr).cast(cls.type_t().pointer()).dereference())
	@classmethod
	def type_t(cls):
		return gdb.lookup_type('struct rb_node')
	def __str__(self):
		out = 'rb_node=' + tohex64(self.address) + ' par_clr=' + tohex64(self.rb_parent_color)
		return out
	def enum_childs(self):
		childs = []
		left = self.rb_left()
		right = self.rb_right()
		if left != None:
			childs.append(left)
			childs.extend(left.enum_childs())
		if right != None:
			childs.append(right)
			childs.extend(right.enum_childs())
		return childs

class rb_root():
	def __init__(self, v):
		self.v = v
		if self.v['rb_node']:
			self.rb_node = rb_node.ptr(long(self.v['rb_node'].dereference().address))
		self.address = long(self.v.address)
	
	def enum_nodes(self):
		nodes = []
		node = self.rb_node
		if node != None:
			nodes.append(node)
			nodes.extend(node.enum_childs())
		return nodes

	@classmethod
	def ptr(cls, addr):
		return cls(gdb.Value(addr).cast(cls.type_t().pointer()).dereference())
	@classmethod
	def type_t(cls):
		return gdb.lookup_type('struct rb_root')
	def __str__(self):
		out = 'rb_root=' + tohex64(self.address) + '\n'
		for n in self.enum_nodes():
			out+= '\t' + str(n) + '\n'
		return out

class address_space():
	def __init__(self, v):
		self.v = v
		self.address = long(self.v.address)
	@classmethod
	def ptr(cls, addr):
		return cls(gdb.Value(addr).cast(cls.type_t().pointer()).dereference())
	@classmethod
	def type_t(cls):
		return gdb.lookup_type('struct address_space')
	def __str__(self):
		out = 'address_space=' + tohex64(self.address)
		return out

class page():
	sz = 0
	def __init__(self, v):
		self.v = v
		if self.v['mapping']:
			self.mapping = address_space.ptr(long(self.v['mapping'].dereference().address))
		else:
			self.mapping = None
		self.address = int_addr(self.v.address)
		self.pfn = self.page_to_pfn()
		self.va = self.page_address()

	@classmethod
	def vmmemmap_start(cls):
		return int('0xffffea0000000000', 16)
	@classmethod
	def page_offset(cls):
		return int('0xffff880000000000', 16)

	@classmethod
	def page_shift(cls):
		return 12
	
	@classmethod
	def size(cls):
		if cls.sz == 0:
			cls.sz = long(gdb.parse_and_eval("sizeof(struct page)"))
		return cls.sz

	@classmethod
	def ptr(cls, addr):
		return cls(gdb.Value(addr).cast(cls.type_t().pointer()).dereference())
	@classmethod
	def type_t(cls):
		return gdb.lookup_type('struct page')
	def __str__(self):
		out = 'page=' + tohex64(self.address) + ' pfn=' + tohex64(self.pfn) + ' va=' + tohex64(self.va) + '\n'
		if self.mapping != None:
			out+= '\t' + str(self.mapping) + '\n'
		return out
	def page_address(self):
		return page.page_offset() + (self.page_to_pfn() << self.page_shift())

	def page_to_pfn(self):
		return (self.address - page.vmmemmap_start())/page.size()

