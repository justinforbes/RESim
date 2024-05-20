#!/usr/bin/env python3
import procTrace
import os
import sys
import glob
'''
Given a path to a directory containing a procTrace.txt and syscall_trace.txt (generated by @cgc.traceProcess(),
identify and report on sockets shared between processes as well as externally visible
sockets.  Alternately provide a path to directory containing just the syscall trace.
'''
def getTokValue(line, field, debug=False):
        if line is None:
            return None
        retval = None
        dashes = line[10:12]
        if debug:
            print('dashes %s' % dashes)
        if len(line) > 12 and line[10:12] == '--':
            parse_this = line[12:]
        else:
            parse_this = line
        if debug:
            print('parse_this: %s' % parse_this)
        parts = parse_this.split()
        for i in range(len(parts)-1):
             if debug:
                 print('does %s start with %s' % (parts[i], field))
             if parts[i].startswith(field+':'):
                 fparts = parts[i].strip().split(':', 1)
                 if len(fparts) > 1 and len(fparts[1])>0:
                     retval = fparts[1].strip(',')
                 else:
                     try:
                         retval = parts[i+1]
                     except:
                         print('no next field after %s in %s' % (field, line))
                 retval = retval.strip()
                 break
        return retval

    
class NetLinks():
                     
    def __init__(self, path):
        sock_start = 'socket - socket tid:'
        sock_sock = 'return from socketcall socket'
        recv_from = '- recvfrom'
        send_to = '- sendto'
        self.proc_trace = None
        if os.path.isfile(path):
            syscall_file = path
        else:
            proc_trace_file = os.path.join(path, 'procTrace.txt')
            if os.path.isfile(proc_trace_file):
                self.proc_trace = procTrace.ProcTrace(proc_trace_file) 
            syscall_file = os.path.join(path, 'syscall_trace.txt')
            if not os.path.isfile(syscall_file):
                syscall_file = glob.glob('%s/syscall_trace*' % path)[0]
                print('Using syscall file %s' % syscall_file)

        self.sock_socks = {}
        self.sock_start = {}
        self.file_sock_binders = {}
        self.file_sock_connectors = {}
        self.port_sock_binders = {}
        self.ext_port_sock_binders = {}
        self.port_sock_connectors = {}
        self.ext_port_sock_connectors = {}
        self.recvfrom_addrs = {}
        self.send_to = {}

        with open(syscall_file) as fh:
            for line in fh:
                if sock_start in line:
                    tid_tok = getTokValue(line, 'tid')
                    type_tok = getTokValue(line, 'type')
                    self.sock_start[tid_tok] = type_tok
                elif sock_sock.lower() in line.lower():
                    tid_tok = getTokValue(line, 'tid')
                    if tid_tok not in self.sock_socks:
                        self.sock_socks[tid_tok] = {}
                    fd_tok = getTokValue(line, 'FD')
                    if tid_tok in self.sock_start:
                        self.sock_socks[tid_tok][fd_tok] = self.sock_start[tid_tok]
                    #print('saved %s' % self.sock_socks[tid_tok][fd_tok]) 
                elif self.isBind(line):
                    tid_tok = getTokValue(line, 'tid')
                    pname = self.getPname(line)
                    fd_tok = getTokValue(line, 'FD')
                    parts = line.split()
                    if 'AF_LOCAL' in line:
                        sock_file = parts[-1]
                        self.file_sock_binders[sock_file] = pname
                    elif 'AF_INET' in line:
                        #addr_port = parts[-1]
                        addr_port = getTokValue(line, 'address')
                        if ':' in addr_port:
                            addr, port = addr_port.split(':')
                        else:
                            print('failed to get address/port token %s from %s' % (addr_port, line))
                            exit(1)
                        if tid_tok in self.sock_socks and fd_tok in self.sock_socks[tid_tok]:
                            contype = self.sock_socks[tid_tok][fd_tok]
                            #print('addr-port %s contype %s' % (addr_port, contype))
                            if contype == '2' or contype == 'SOCK_DGRAM':
                                port = port+'-UDP' 
                                addr_port = addr_port+'-UDP' 
                        elif 'type: ' in line:
                            sock_type = getTokValue(line, 'type')
                            if sock_type == 'SOCK_DGRAM':
                                port = port+'-UDP' 
                                addr_port = addr_port+'-UDP' 
                        if '(random)' in line:
                            addr_port = addr_port+'(random)' 
                        if addr.startswith('127.'):
                            ''' internal '''
                            self.port_sock_binders[port] = pname
                        elif addr.startswith('0.0.0'):
                            ''' both '''
                            self.port_sock_binders[port] = pname
                            self.ext_port_sock_binders[addr_port] = pname
                        else:
                            ''' external '''
                            self.ext_port_sock_binders[addr_port] = pname
                        #if pname is None:
                        #    print('binder port add %s none for tid %s' % (port, tid_tok))
                        #else:
                        #    print('binder port add %s as %s tid %s' % (port, pname, tid_tok))
                    else:
                        continue
                elif self.isConnect(line):
                    parts = line.split()
                    tid_tok = parts[3]
                    fd = getTokValue(line, 'FD')
                    pname = self.getPname(line)
                    #tid_id = None
                    #if ':' in tid_tok:
                    #    tid_id = tid_tok.split(':')[1]
                    #    pname = self.proc_trace.getPname(tid_id)
                    #else:
                    #    tid_id = getTokValue(line, 'tid', debug=True)
                    #if tid_id is None:
                    #    print('failed to get tid from %s' % line)
                    #    exit(1) 
                    if 'AF_LOCAL' in line:
                        sock_file_index = parts.index('sa_data:')
                        sock_file = parts[sock_file_index+1]
                        if sock_file not in self.file_sock_connectors:
                            self.file_sock_connectors[sock_file] = []
                        
                        if pname not in self.file_sock_connectors[sock_file]:
                            self.file_sock_connectors[sock_file].append(pname)
                    elif 'AF_INET' in line:
                        addr_port_index = parts.index('address:')
                        addr_port = parts[addr_port_index+1]
                        if ':' in addr_port:
                            addr, port = addr_port.split(':')
                        else:
                            print('failed to get address/port from %s' % line)
                            exit(1)
                        #print('%s %s' %  (pname, line))
                        if not addr.startswith('0.0.') and not addr.startswith('127.'):
                            ''' external ''' 
                            if addr_port not in self.ext_port_sock_connectors:
                                self.ext_port_sock_connectors[addr_port] = []
                            if pname not in self.ext_port_sock_connectors[addr_port]:
                                self.ext_port_sock_connectors[addr_port].append(pname)
                            #if pname.endswith('floatdruif'):
                            #    print('wtf: %s' % self.ext_port_sock_connectors[addr_port])
                        else:
                            ''' internal '''
                            #print('is internal port %s' % port)
                            if port not in self.port_sock_connectors:
                                self.port_sock_connectors[port] = []
                            if pname not in self.port_sock_connectors[port]:
                                self.port_sock_connectors[port].append(pname)
                    else:
                        continue
                elif recv_from in line and 'AF_INET' in line:
                    addr_tok = getTokValue(line, 'address')
                    pname = self.getPname(line)
                    if pname not in self.recvfrom_addrs:
                        self.recvfrom_addrs[pname] = []
                    if addr_tok not in self.recvfrom_addrs[pname]:
                        self.recvfrom_addrs[pname].append(addr_tok)
                elif send_to in line and 'AF_INET' in line:
                    addr_tok = getTokValue(line, 'address')
                    pname = self.getPname(line)
                    if pname not in self.send_to:
                        self.send_to[pname] = []
                    if addr_tok not in self.send_to[pname]:
                        self.send_to[pname].append(addr_tok)

    def isBind(self, line):
        sock_bind = 'return from socketcall bind'
        win_bind = 'return from deviceiocontrolfile'
        if sock_bind.lower() in line.lower() or (win_bind.lower() in line.lower() and 'bind' in line.lower()):
            return True
        else:
            return False

    def isConnect(self, line):
        sock_connect = 'connect tid'
        if sock_connect in line or 'deviceiocontrolfile connect' in line.lower():
            return True
        else:
            return False

    def showPorts(self):
        print('External connections') 
        for addr_port in sorted(self.ext_port_sock_connectors):
            for pname in self.ext_port_sock_connectors[addr_port]:
                print('\t%s => %s' % (pname, addr_port))           
        connectors = {}
        for port in self.port_sock_connectors:
            if port in self.port_sock_binders:
                binder = self.port_sock_binders[port]
            else:
                binder = 'unknown'
            for pname in self.port_sock_connectors[port]:
                #print('%s => %s => %s' % (pname, port, binder))           
                if pname not in connectors:
                    connectors[pname] = []
                connectors[pname].append((port, binder))
        print('Internal networking') 
        for pname in sorted(connectors):
            items = connectors[pname]
            for port, binder in items:
                print('\t%s => %s => %s' % (pname, port, binder))           
                
        print('Externally visiable bindings (I => connected by internal process)')
        for addr_port in sorted(self.ext_port_sock_binders):
            addr, port = addr_port.split(':')
            if port in self.port_sock_connectors:        
                print('\tI      %s => %s' % (addr_port, self.ext_port_sock_binders[addr_port]))           
            else:
                print('\t       %s => %s' % (addr_port, self.ext_port_sock_binders[addr_port]))           

        print('Addresses given to recvfrom:')
        for pname in self.recvfrom_addrs:
            for addr in self.recvfrom_addrs[pname]:
                print('\t       %s => %s' % (addr, pname)) 

        print('Addresses given to sendto:')
        for pname in self.send_to:
            for addr in self.send_to[pname]:
                print('\t       %s => %s' % (pname, addr)) 

    def showFileSocks(self):
        connectors = {}
        for fname in self.file_sock_connectors:
            if fname in self.file_sock_binders:
                binder = self.file_sock_binders[fname]
            else:
                binder = 'unknown'
            for pname in self.file_sock_connectors[fname]:
                if pname is None:
                    continue
                if pname not in connectors:
                    connectors[pname] = []
                connectors[pname].append((fname, binder))
        print('Internal sockets') 
        for pname in sorted(connectors):
            items = connectors[pname]
            for fname, binder in items:
                print('\t%s => %s => %s' % (pname, fname, binder))           

    def getPname(self, line):
        tid_tok = getTokValue(line, 'tid')
        if self.proc_trace is not None:
            pname = self.proc_trace.getPname(tid_tok)
        else:
            # no proc trace available, just parse the log file line for the comm
            if '--pid:' in line:
                # assume windows format
                pname = line.split()[1]
            else:
                if 'tid:' in line:
                    pre_tid, post_tid = line.split('tid:',1)
                    parts = post_tid.split()
                    pname = parts[1]
        return pname
   
        
if __name__ == '__main__':
    traces = sys.argv[1]
    nl = NetLinks(traces) 
    nl.showPorts()
    nl.showFileSocks()
