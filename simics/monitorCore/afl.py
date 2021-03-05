import backStop
import os
import shutil
import time
import socket
import sys
import pickle
import struct
import cli
import stopFunction
from simics import *
RESIM_MSG_SIZE=80
class AFL():
    def __init__(self, top, cpu, cell_name, coverage, backstop, mem_utils, dataWatch, snap_name, lgr, fd=None, packet_count=1, stop_on_read=False):
        ''' *** FIX THIS ***'''
        self.pad_to_size = 1448
        #self.pad_to_size = 1333
        self.pad_char = chr(0)
        self.cpu = cpu
        self.cell_name = cell_name
        self.lgr = lgr
        self.top = top
        self.mem_utils = mem_utils
        self.fd = fd
        self.stop_on_read = stop_on_read
        self.dataWatch = dataWatch
        self.coverage = coverage
        self.packet_count = packet_count
        self.afl_packet_count = None
        self.current_packet = 1
        self.path = '/home/mike/SEED/afl/target_input.io'
        self.backstop = backstop
        self.stop_hap = None
        self.return_ip = None
        self.call_ip = None
        self.call_break = None
        self.call_hap = None
        self.in_data = None
        self.backstop.setCallback(self.whenDone)
        ''' careful changing this, may hit backstop before crashed process killed '''
        #self.backstop_cycles =  500000
        if stop_on_read:
            self.backstop_cycles = 0
        else:
            self.backstop_cycles =   100000
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(2)
        self.server_address = ('localhost', 8765)
        self.iteration = 1
        self.pid = self.top.getPID()

        if self.cpu.architecture == 'arm':
            lenreg = 'r0'
        else:
            lenreg = 'eax'
        self.len_reg_num = self.cpu.iface.int_register.get_number(lenreg)
        if fd is not None:
            self.prepInject(snap_name)
        else:
            self.loadPickle(snap_name)
            self.finishInit()
     
    def finishInit(self): 
        self.top.removeDebugBreaks(keep_watching=False, keep_coverage=False)
        self.coverage.enableCoverage(self.pid, backstop=self.backstop, backstop_cycles=self.backstop_cycles, afl=True)
        cli.quiet_run_command('disable-reverse-execution')
        cli.quiet_run_command('enable-unsupported-feature internals')
        cli.quiet_run_command('save-snapshot name = origin')
        self.synchAFL()

    def rmStopHap(self):
        if self.stop_hap is not None:
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None

    def stopHap(self, dumb, one, exception, error_string):
        if self.stop_hap is not None:
            #self.stop_hap = None
            #self.lgr.debug('afl stopHap')
            trace_bits = self.coverage.getTraceBits()
           
            #self.lgr.debug('afl stopHap bitfile iteration %d cycle: 0x%x' % (self.iteration, self.cpu.cycles))
            status = self.coverage.getStatus()
            if status != 0:
                self.lgr.debug('afl stopHap status not zero %d iteration %d, data written to /tmp/icrashed' %(status, self.iteration)) 
                with open('/tmp/icrashed', 'w') as fh:
                    fh.write(self.in_data)
            self.sendMsg('resim_done iteration: %d status: %d' % (self.iteration, status))
            try: 
                self.sock.sendall(trace_bits)
            except:
                self.lgr.debug('AFL went away while we were sending trace_bits')
                self.rmStopHap()
                return
            if status != 0:
                self.lgr.debug('afl stopHap status back from sendall trace_bites')
            self.iteration += 1 
            SIM_run_alone(self.goN, status)


    def goN(self, status):
        if status != 0:
            self.lgr.debug('afl goN after crash. Call getMsg')
        self.current_packet = 1
        ''' get all data from afl '''
      
        self.in_data = self.getMsg()
        if self.in_data is None:
            self.lgr.error('Got None from afl')
            self.rmStopHap()
            return
       
        
        cli.quiet_run_command('restore-snapshot name=origin')

        if status != 0:
            self.lgr.debug('afl goN after crash. restored snapshot after getting %d bytes from afl' % len(self.in_data))
       
        current_length = len(self.in_data)
        self.afl_packet_count = self.packet_count
        if self.packet_count > 1 and current_length < (self.pad_to_size*(self.packet_count-1)):
            #self.lgr.debug('afl packet count of %d and size of %d, but only %d bytes from AFL.  Cannot do it.' % (self.packet_count, self.pad_to_size, current_length))
            self.afl_packet_count = (current_length / self.pad_to_size) + 1
       

        self.addr, max_len = self.dataWatch.firstBufferAddress()
        if self.addr is None:
            self.lgr.error('AFL, no firstBufferAddress found')
            return

        tot_length = current_length
        pad_count = 0
        if self.afl_packet_count == 1:  
            pad_count = self.pad_to_size - current_length
            self.mem_utils.writeString(self.cpu, self.addr, self.in_data) 
            if pad_count > 0:
                b = bytearray(pad_count)
                self.mem_utils.writeString(self.cpu, self.addr+current_length, b) 
                tot_length += pad_count
            if self.backstop_cycles > 0:
                self.backstop.setFutureCycleAlone(self.backstop_cycles)
        else:
            first_data = self.in_data[0:self.pad_to_size]
            self.mem_utils.writeString(self.cpu, self.addr, first_data) 
        

        if (self.afl_packet_count > 1 or self.stop_on_read) and self.call_hap is None:
            cell = self.top.getCell()
            self.call_break = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, self.call_ip, 1, 0)
            self.call_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.callHap, None, self.call_break)
            #self.lgr.debug('afl go set call break at 0x%x and hap, cycle is 0x%x' % (self.call_ip, self.cpu.cycles))
         
        self.cpu.iface.int_register.write(self.len_reg_num, tot_length)
        self.coverage.doCoverage()
        #self.lgr.debug('afl, did coverage, cycle: 0x%x' % self.cpu.cycles)
        if self.stop_hap is None:
            self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.stopHap,  None)
        if status != 0:
            self.lgr.debug('afl goN after call continue')
        cli.quiet_run_command('c') 

    def callHap(self, dumb, third, break_num, memory):
        if self.call_hap is None:
            return
        this_pid = self.top.getPID()
        if this_pid != self.pid:
            self.lgr.debug('afl callHap wrong pid got %d wanted %d' % (this_pid, self.pid))
            return
        #self.lgr.debug('afl callHap cycles 0x%x' % self.cpu.cycles)
        if self.stop_on_read:
            #self.lgr.debug('afl callHap stop on read')
            SIM_break_simulation('stop on read')
            return
        offset = self.current_packet * self.pad_to_size 
        if offset > len(self.in_data):
            self.lgr.error('afl callHap computed offset is %d, but data from afl is only %d bytes' % (offset, len(self.in_data)))
            SIM_break_simulation('broken offset')
            SIM_run_alone(self.dellCalHap, None)
            return
        if (offset+self.pad_to_size) > len(self.in_data):
            this_data = self.in_data[offset:]
        else:
            this_data = self.in_data[offset:offset+self.pad_to_size]
        self.mem_utils.writeString(self.cpu, self.addr, this_data) 
        pad_count = self.pad_to_size - len(this_data)
        if pad_count > 0:
            b = bytearray(pad_count)
            self.mem_utils.writeString(self.cpu, self.addr+len(this_data), b) 
        self.cpu.iface.int_register.write(self.len_reg_num, self.pad_to_size)
        self.mem_utils.setRegValue(self.cpu, 'pc', self.return_ip) 
        #self.lgr.debug('afl callHap set ip to 0x%x' % self.return_ip) 
        self.current_packet += 1
        if self.current_packet >= self.afl_packet_count:
            SIM_run_alone(self.delCallHap, None)
            if self.backstop_cycles > 0:
                self.backstop.setFutureCycleAlone(self.backstop_cycles)

    def delCallHap(self, dumb):
        SIM_delete_breakpoint(self.call_break)
        SIM_hap_delete_callback_id('Core_Breakpoint_Memop', self.call_hap)
        self.call_hap = None

    def whenDone(self):
        #self.lgr.debug('afl whenDone callback')
        pass

    def synchAFL(self):
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = ('localhost', 8765)
        self.sock.connect(server_address)
        self.coverage.doCoverage()
        num_blocks = self.coverage.getNumBlocks()
        self.sendMsg('hi from resim')
        reply = self.getMsg()
        self.lgr.debug('afl synchAFL reply from afl: %s' % reply)

    def sendMsg(self, msg):
        msg_size = len(msg)
        ms = struct.pack("i", msg_size) 
        combine=''.join((ms,msg))
        try:
            self.sock.sendall(combine)
        except:
            self.rmStopHap()
            print('AFL went away');
            self.lgr.debug('AFL went away while in sendMsg');
        #self.lgr.debug('sent to AFL len %d: %s' % (msg_size, msg))

    def getMsg(self):
        data = self.sock.recv(4)
        #self.lgr.debug('got data len %d %s' % (len(data), data))
        if data is None or len(data) == 0:
            self.sock.close()
            return None
        msg_len = struct.unpack("i", data)[0]
        #self.lgr.debug('getMsg got msg_len of %d' % msg_len)
        msg = "" 
        expected = msg_len
        amount_received = 0
        while amount_received < msg_len:
            data = self.sock.recv(expected)
            if data is None or len(data) == 0:
                self.sock.close()
                self.rmStopHap()
                self.lgr.debug("got nothing from afl")
                return None
            #self.lgr.debug('got from afl: %s' % data)
            amount_received += len(data)
            expected = expected - len(data)
            msg = msg+data
        return msg
 
    def instrumentAlone(self, snap_name): 
        self.top.removeDebugBreaks(keep_watching=False, keep_coverage=True)
        ''' go forward one to user space and record the return IP '''
        SIM_run_command('pselect %s' % self.cpu.name)
        SIM_run_command('si')
        self.return_ip = self.top.getEIP(self.cpu)
        ret_cycle = self.cpu.cycles
        pid = self.top.getPID()
        self.lgr.debug('instrument snap_name %s stepped to return IP: 0x%x pid:%d cycle is 0x%x' % (snap_name, self.return_ip, pid, self.cpu.cycles))
        ''' return to the call to record that IP '''
        frame, cycle = self.top.getRecentEnterCycle()
        previous = cycle - 1
        SIM_run_command('skip-to cycle=%d' % previous)
        self.call_ip = self.top.getEIP(self.cpu)
        pid = self.top.getPID()
        self.lgr.debug('instrument  skipped to call IP: 0x%x pid:%d callnum: %d cycle is 0x%x' % (self.call_ip, pid, frame['syscall_num'], self.cpu.cycles))
        ''' skip back to return so the snapshot is ready to inject input '''
        SIM_run_command('skip-to cycle=%d' % ret_cycle)
        self.pickleit(snap_name)
        #self.finishInit()

    def instrumentIO(self, snap_name):
        self.lgr.debug("in instrument IO");
        SIM_run_alone(self.instrumentAlone, snap_name)

    def prepInject(self, snap_name):
        ''' Use runToIO to find location of desired input call.  Set callback to instrument the call and return '''
        f1 = stopFunction.StopFunction(self.instrumentIO, [snap_name], nest=False)
        flist = [f1]
        self.top.runToIO(self.fd, flist_in=flist)

    def pickleit(self, name):
        self.top.writeConfig(name)
        pickDict = {}
        pickDict['call_ip'] = self.call_ip
        pickDict['return_ip'] = self.return_ip
        afl_file = os.path.join('./', name, self.cell_name, 'afl.pickle')
        pickle.dump( pickDict, open( afl_file, "wb") ) 

    def loadPickle(self, name):
        afl_file = os.path.join('./', name, self.cell_name, 'afl.pickle')
        if os.path.isfile(afl_file):
            self.lgr.debug('afl pickle from %s' % afl_file)
            so_pickle = pickle.load( open(afl_file, 'rb') ) 
            #print('start %s' % str(so_pickle['text_start']))
            self.call_ip = so_pickle['call_ip']
            self.return_ip = so_pickle['return_ip']