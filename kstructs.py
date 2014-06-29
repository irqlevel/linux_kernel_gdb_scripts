import gdb
import traceback
import inspect
import sys
import os

class task_struct():
	def __init__(self, v):
		self.v = v
		#print 'task=', self.v.address
		self.pid = v['pid']
		self.state = v['state']
		self.flags = v['flags']
		self.stack = v['stack']
		self.comm = v['comm'].string()
		if self.v['mm'] != 0:
			self.mm = mm_struct(self.v['mm'].dereference())
		else:
			self.mm = None
	def __str__(self):
		out = 'task=' + str(self.v.address) + ' flags=' + hex(long(self.flags)) + ' state=' + str(self.state) 
		out += ' stack=' + str(self.stack) + '\n'
		out += ' pid=' + str(self.pid) + ' comm=' + self.comm
		if self.mm != None:
			out += '\n'
			out += ' ' + str(self.mm)
		return out

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

class file():
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
		
class module():
	def __init__(self, v):
		self.v = v
		self.name = self.v['name'].string()
		self.args = self.v['args'].string()
		self.module_core = self.v['module_core']
		self.core_size = self.v['core_size']
		self.core_text_size = self.v['core_text_size']
	def __str__(self):
		out = 'module=' + str(self.v.address) + ' name=' + self.name + ' module_core=' + str(self.module_core) 
		out+= ' core_size=' + str(self.core_size) + ' core_text_size=' + str(self.core_text_size)
		return out

class vfsmount():
	def __init__(self, v):
		self.v = v
		#print 'vfs_mount=', self.v.address
		self.mnt_root = dentry(self.v['mnt_root'].dereference())

