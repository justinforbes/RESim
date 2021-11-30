import backStop
import os
import shutil
import time
import socket
import sys
import pickle
import struct
import json
import cli
import stopFunction
import writeData
import imp 
#import tracemalloc
from simics import *
RESIM_MSG_SIZE=80
class AFL():
    def __init__(self, top, cpu, cell_name, coverage, backstop, mem_utils, dataWatch, snap_name, context_manager, lgr,
                 packet_count=1, stop_on_read=False, fname=None, linear=False, target=None, create_dead_zone=False, port=8765, 
                 one_done=False):
        pad_env = os.getenv('AFL_PAD') 
        self.lgr = lgr
        if pad_env is not None:
            try:
                self.pad_to_size = int(pad_env)
            except:
                self.lgr.error('Bad AFL_PAD value %s' % pad_env)
                return
        else: 
            self.pad_to_size = 0
        self.udp_header = os.getenv('AFL_UDP_HEADER')
        if packet_count > 1 and not (self.udp_header is not None or self.pad_to_size > 0):
            self.lgr.error('Multi-packet requested but no pad or UDP header has been given in env variables')
            return
        self.filter_module = None
        self.packet_filter = os.getenv('AFL_PACKET_FILTER')
        if self.packet_filter is not None:
            file_path = './%s.py' % self.packet_filter
            abs_path = os.path.abspath(file_path)
            if os.path.isfile(abs_path):
                self.filter_module = imp.load_source(self.packet_filter, abs_path)
                self.lgr.debug('afl using AFL_PACKET_FILTER %s' % self.packet_filter)
            else:
                self.lgr.error('failed to find filter at %s' % self.packet_filter)
                return
            '''
            module_name = self.packet_filter
            spec = importlib.util.spec_from_file_location(module_name, file_path)
            filter_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(flter_module)
            '''

        self.pad_char = chr(0)
        self.cpu = cpu
        self.cell_name = cell_name
        self.top = top
        self.mem_utils = mem_utils
        self.stop_on_read = stop_on_read
        self.dataWatch = dataWatch
        self.coverage = coverage
        self.context_manager = context_manager
        self.linear = linear
        # For multi-packet UDP.  afl_packet_count may be adjusted less than given packet count.
        self.packet_count = packet_count
        self.afl_packet_count = None
        self.current_packet = 0
        self.backstop = backstop
        self.stop_hap = None
        self.call_break = None
        self.call_hap = None
        self.in_data = None
        self.orig_in_data = None
        self.orig_data_length = 0
        self.write_data = None
        self.target = target
        self.create_dead_zone = create_dead_zone
        self.backstop.setCallback(self.whenDone)
        self.port = port
        self.one_done = one_done
        sor = os.getenv('STOP_ON_READ')
        if sor is not None and sor.lower() == 'true':
            self.stop_on_read = True
        # TBD why are sor and backstop mutually exclusive?
        if stop_on_read:
            self.backstop_cycles = 0
        else:
            if os.getenv('BACK_STOP_CYCLES') is not None:
                self.backstop_cycles =   int(os.getenv('BACK_STOP_CYCLES'))
                self.lgr.debug('afl BACK_STOP_CYCLES is %d' % self.backstop_cycles)
            else:
                self.lgr.warning('no BACK_STOP_CYCLES defined, using default of 100000')
                self.backstop_cycles =   100000
                
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(2)
        self.server_address = ('localhost', self.port)
        self.iteration = 1
        self.pid = self.top.getPID()
        self.total_hits = 0
        self.bad_trick = False
        self.trace_snap1 = None
        self.empty_trace_bits = None
        if self.cpu.architecture == 'arm':
            lenreg = 'r0'
        else:
            lenreg = 'eax'
        self.len_reg_num = self.cpu.iface.int_register.get_number(lenreg)
        self.pc_reg = self.cpu.iface.int_register.get_number('pc')
        self.addr = None
        self.orig_buffer = None
        hang_cycles = 90000000
        hang = os.getenv('HANG_CYCLES')
        if hang is not None:
            hang_cycles = int(hang)
        self.backstop.setHangCallback(self.coverage.recordHang, hang_cycles)
        self.lgr.debug('AFL init from snap %s' % snap_name)

        self.snap_name = snap_name
        self.loadPickle(snap_name)
        if target is None:
            self.top.removeDebugBreaks(keep_watching=False, keep_coverage=False)
            if self.orig_buffer is not None:
                self.lgr.debug('restored %d bytes 0x%x context %s' % (len(self.orig_buffer), self.addr, self.cpu.current_context))
                self.mem_utils.writeString(self.cpu, self.addr, self.orig_buffer)
            self.coverage.enableCoverage(self.pid, backstop=self.backstop, backstop_cycles=self.backstop_cycles, 
                afl=True, fname=fname, linear=linear, create_dead_zone=self.create_dead_zone)
            cli.quiet_run_command('disable-reverse-execution')
            cli.quiet_run_command('enable-unsupported-feature internals')
            cli.quiet_run_command('save-snapshot name = origin')
            self.coverage.doCoverage()
            self.synchAFL()
            self.lgr.debug('afl done init, num packets is %d stop_on_read is %r' % (self.packet_count, self.stop_on_read))
            self.fault_hap = None
            #tracemalloc.start()
            # hack around Simics model bug
            #self.fixFaults()
        else:
            self.lgr.debug('afl use target %s, call debug' % target)
            ''' need a bookmark to get back to here after setting up debug process '''
            self.top.resetOrigin()
   
            self.top.debugProc(target, self.aflInitCallback)
        #self.coverage.watchExits()
    

    def aflInitCallback(self):
        self.lgr.debug('afl aflInitCallback')
        ''' Now in target process'''
        self.coverage = self.top.getCoverage()
        self.pid = self.top.getPID()
        self.top.removeDebugBreaks(keep_watching=False, keep_coverage=False)
        self.coverage.enableCoverage(self.pid, backstop=self.backstop, backstop_cycles=self.backstop_cycles, 
            afl=True)
        self.coverage.doCoverage()
        cmd = 'skip-to bookmark = bookmark0'
        cli.quiet_run_command(cmd)
        cli.quiet_run_command('disable-reverse-execution')
        cli.quiet_run_command('enable-unsupported-feature internals')
        cli.quiet_run_command('save-snapshot name = origin')
        self.synchAFL()
        self.lgr.debug('afl done init, num packets is %d stop_on_read is %r' % (self.packet_count, self.stop_on_read))
        self.fault_hap = None
        self.top.noWatchSysEnter()
        self.goN(0) 


    def rmStopHap(self):
        if self.stop_hap is not None:
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None
            #self.lgr.debug('afl removed stop hap')

    def goAlone(self, dumb):
        SIM_run_command('c') 
   
    def finishUp(self): 
            if self.bad_trick and self.empty_trace_bits is not None:
                trace_bits = self.empty_trace_bits
            else:
                trace_bits = self.coverage.getTraceBits()
                if self.empty_trace_bits is None:
                    self.empty_trace_bits = trace_bits
            self.total_hits += self.coverage.getHitCount() 
            if self.iteration % 100 == 0:
                avg = self.total_hits/100
                self.lgr.debug('afl average hits in last 100 iterations is %d' % avg)
                self.total_hits = 0
                struct._clearcache()
            #self.lgr.debug('afl stopHap bitfile iteration %d cycle: 0x%x' % (self.iteration, self.cpu.cycles))
            status = self.coverage.getStatus()
            if status == 1:
                self.lgr.debug('afl finishUp status reflects crash %d iteration %d, data written to /tmp/icrashed' %(status, self.iteration)) 
                with open('/tmp/icrashed', 'wb') as fh:
                    fh.write(self.orig_in_data)
                self.lgr.debug('afl finishUp cpu context is %s' % self.cpu.current_context)
            elif status == 2:
                self.lgr.debug('afl finishUp status reflects hang %d iteration %d, data written to /tmp/ihung' %(status, self.iteration)) 
                with open('/tmp/ihung', 'wb') as fh:
                    fh.write(self.orig_in_data)
                self.lgr.debug('afl finishUp cpu context is %s' % self.cpu.current_context)

            if self.one_done:
                self.sock.close()
                self.coverage.stopCover()
                self.lgr.debug('afl one and done, removed coverage breaks')
                return

            ''' Send the status message '''
            self.sendMsg('resim_done iteration: %d status: %d size: %d' % (self.iteration, status, self.orig_data_length))
            try: 
                self.sock.sendall(trace_bits)
                pass
            except:
                self.lgr.debug('AFL went away while we were sending trace_bits')
                self.rmStopHap()
                return
            if status != 0:
                self.lgr.debug('afl stopHap status back from sendall trace_bits')
            '''
            if self.iteration == 1:
                self.trace_snap1 = tracemalloc.take_snapshot()
            elif self.iteration == 1000:
                trace_snap2 = tracemalloc.take_snapshot()
                top_stats = trace_snap2.compare_to(self.trace_snap1, 'lineno')
                self.lgr.debug('found %d topstats' % len(top_stats))
                for stat in top_stats[:10]:
                    self.lgr.debug(stat)
                SIM_run_command('q')
            '''
            self.iteration += 1 
            self.in_data = self.getMsg()
            if self.in_data is None:
                self.lgr.error('Got None from afl')
                self.rmStopHap()
                return
            SIM_run_alone(self.goN, status)

    def stopHap(self, dumb, one, exception, error_string):
        ''' Entered when the backstop is hit'''
        ''' Also if coverage record exit is hit '''
        #self.lgr.debug('afl stopHap')
        if self.stop_hap is None:
            return
        self.finishUp()

    def goN(self, status):
        if status != 0:
            self.lgr.debug('afl goN after crash. Call getMsg')
        ''' Only applies to multi-packet UDP fu '''
        self.current_packet = 0
        self.bad_trick = False
        ''' If just starting, get data from afl, otherwise, was read from stopHap. '''
        if self.stop_hap is None:
            self.in_data = self.getMsg()
            if self.in_data is None:
                self.lgr.error('Got None from afl')
                return
        self.orig_data_length = len(self.in_data)
        self.orig_in_data = self.in_data
        
        cli.quiet_run_command('restore-snapshot name=origin')
        #self.top.restoreRESimContext()

        #self.lgr.debug('got %d of data from afl iteration %d' % (len(self.in_data), self.iteration))
        if status != 0:
            self.lgr.debug('afl goN after crash. restored snapshot after getting %d bytes from afl' % len(self.in_data))
       
        current_length = len(self.in_data)
        self.afl_packet_count = self.packet_count
        if self.udp_header is None and self.packet_count > 1 and current_length < (self.pad_to_size*(self.packet_count-1)):
            self.lgr.debug('afl packet count of %d and size of %d, but only %d bytes from AFL.  Cannot do it.' % (self.packet_count, self.pad_to_size, current_length))
            self.afl_packet_count = (current_length / self.pad_to_size) + 1
            self.lgr.debug('afl packet count now %d' % self.afl_packet_count)
       

        if self.addr is None:
           self.addr, max_len = self.dataWatch.firstBufferAddress()
           if self.addr is None:
               self.lgr.error('AFL, no firstBufferAddress found')
               return

        if self.create_dead_zone:
            self.lgr.debug('afl goN dead zone iteration %d' % self.iteration)
        ''' clear the bit_trace '''
        #self.lgr.debug('afl goN call doCoverage')
        if self.linear:
            #self.lgr.debug('afl, linear use context manager to watch tasks')
            self.context_manager.restoreDebugContext()
            self.context_manager.watchTasks()
        self.coverage.doCoverage()

        #self.lgr.debug('afl, did coverage, cycle: 0x%x' % self.cpu.cycles)
        if self.stop_hap is None:
            #self.lgr.debug('afl added stop hap')
            self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.stopHap,  None)
        if status != 0:
            self.lgr.debug('afl goN call continue, cpu cycle was 0x%x context %s' % (self.cpu.cycles, self.cpu.current_context))
            self.coverage.watchExits(pid=self.pid)

        if self.write_data is None:
            self.write_data = writeData.WriteData(self.top, self.cpu, self.in_data, self.afl_packet_count, 
                 self.mem_utils, self.backstop, self.snap_name, self.lgr, udp_header=self.udp_header, 
                 pad_to_size=self.pad_to_size, filter=self.filter_module, backstop_cycles=self.backstop_cycles, force_default_context=True,
                 stop_on_read=self.stop_on_read)
        else:
           self.write_data.reset(self.in_data, self.afl_packet_count, self.addr)

        self.write_data.write()
        #self.lgr.debug('afl goN context %s' % self.cpu.current_context)
        cli.quiet_run_command('c') 

    def whenDone(self):
        #self.lgr.debug('afl whenDone callback')
        pass

    def synchAFL(self):
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = ('localhost', self.port)
        self.lgr.debug('afl conect to port %d' % self.port)
        self.sock.connect(server_address)
        self.sendMsg('hi from resim')
        reply = self.getMsg()
        self.lgr.debug('afl synchAFL reply from afl: %s' % reply)

    def sendMsg(self, msg):
        msg_size = len(msg)
        ms = struct.pack("i", msg_size) 
        #self.sock.sendall(ms+bytes(msg, 'utf8'))
        if sys.version_info[0] == 3:
            try:
                #self.sock.sendall(combine)
                self.sock.sendall(ms+bytes(msg, 'utf8'))
            except:
                self.rmStopHap()
                print('AFL went away');
                self.lgr.debug('AFL went away while in sendMsg');
        else:
            try:
                #self.sock.sendall(combine)
                self.sock.sendall(ms+msg)
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
        msg = bytearray()
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
 

    def loadPickle(self, name):
        afl_file = os.path.join('./', name, self.cell_name, 'afl.pickle')
        if os.path.isfile(afl_file):
            self.lgr.debug('afl pickle from %s' % afl_file)
            so_pickle = pickle.load( open(afl_file, 'rb') ) 
            #print('start %s' % str(so_pickle['text_start']))
            if 'addr' in so_pickle:
                self.addr = so_pickle['addr']
            if 'orig_buffer' in so_pickle:
                self.orig_buffer = so_pickle['orig_buffer']

    def fixFaults(self):
        if self.cpu.architecture == 'arm':
            self.fault_hap = SIM_hap_add_callback_obj_index("Core_Exception", self.cpu, 0,
                 self.faultCallback, self.cpu, 1)

    def faultCallback(self, cpu, one, exception_number):
        if self.fault_hap is not None:
            reg_num = cpu.iface.int_register.get_number("combined_data_fsr")
            fsr = cpu.iface.int_register.read(reg_num)
            if fsr == 2:
               cpu.iface.int_register.write(reg_num,1)
               self.lgr.warning('hacked ARM fsr register from 2 to 1')

