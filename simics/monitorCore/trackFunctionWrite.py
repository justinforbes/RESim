'''
 * This software was created by United States Government employees
 * and may not be copyrighted.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
'''
'''
Record data written by a function from its invocation until its exit.
'''
from simics import *
import memUtils
import writeMarks
class TrackFunctionWrite():
    class WriteData():
        def __init__(self, pc, addr, length):
            self.pc = pc
            self.addr = addr
            self.length = length

    def __init__(self, cpu, cell, param, mem_utils, task_utils, context_manager, lgr):
        self.cpu = cpu
        self.cell = cell
        self.param = param
        self.tid = None
        self.mem_utils = mem_utils
        self.task_utils = task_utils
        self.read_watch_marks = None
        self.write_hap = None
        self.fun = None
        self.fun_entry_hap = None
        self.fun_exit_hap = None
        self.ret_addr = None 
        self.lgr = lgr 
        self.context_manager = context_manager
        ''' Display merged read marks and write marks? '''
        self.show_compare = False
        self.writeMarks = writeMarks.WriteMarks(mem_utils, cpu, lgr)

    
    def trackFunction(self, tid, fun, fun_mgr, read_watch_marks, show_compare):
        self.tid = tid
        self.fun = fun
        self.read_watch_marks = read_watch_marks
        self.show_compare = show_compare
        start, end = fun_mgr.getAddr(fun)
        if start is None:
            self.lgr.error('TrackFunctionWrite, no function found: %s' % fun)         
            return
        self.lgr.debug('trackFunction %s start 0x%x' % (fun, start))
        eip = self.mem_utils.getRegValue(self.cpu, 'pc') 
        cur_fun = fun_mgr.getFun(eip)
        if cur_fun == start:
            ''' TBD need to be be prior to call to record return address '''
            self.lgr.error('TrackFunctionWrite starting in the function %s -- rev to prior' % fun)
            return
        else:
            ''' set break on function entry '''
            proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, start, 1, 0)
            self.fun_entry_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.funEnterHap, None, 
                proc_break, 'track-fun-write-entry')
        self.lgr.debug('trackFunctionWrite for %s 0x%x' % (fun, start))

    def funEnterHap(self, dumb, third, forth, memory):
        if self.fun_entry_hap is None:
            return
        cpu, comm, cur_tid = self.task_utils.curThread() 
        self.lgr.debug('funEnterHap, tid:%s wanted %s' % (cur_tid, self.tid))
        if cur_tid != self.tid:
            return
        self.lgr.debug('funEnterHap, set blanket writes')
        self.blanketWrites()
        self.context_manager.genDeleteHap(self.fun_entry_hap)
        self.fun_entry_hap = None 
        if self.cpu.architecture.startswith('arm'):
            self.ret_addr = self.mem_utils.getRegValue(self.cpu, 'lr') 
        else:
            esp = self.mem_utils.getRegValue(self.cpu, 'esp') 
            self.lgr.debug('funEnterHap sp 0x%x' % esp)
            self.ret_addr = self.mem_utils.readPtr(self.cpu, esp)
            self.lgr.debug('funEnterHap ret 0x%x' % self.ret_addr)
            
        proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, 
                       Sim_Access_Execute, self.ret_addr, 1, 0)
        self.fun_exit_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.funExitHap, None, 
            proc_break, 'track-fun-write-exit')

    def funExitHap(self, dumb, third, forth, memory):
        if self.fun_exit_hap is None:
            return
        cpu, comm, cur_tid = self.task_utils.curThread() 
        if cur_tid != self.tid:
            return
        self.context_manager.genDeleteHap(self.fun_exit_hap)
        self.fun_exit_hap = None 
        self.stopBlanket()
        self.writeMarks.showMarks()
        SIM_break_simulation('out of function %s (or reached limit of write marks)' % self.fun)
        self.compareMarks()
        self.showWriteRanges()
        
    def writeHap(self, dumb, third, forth, memory):
        if self.write_hap is None:
            return
        cpu, comm, cur_tid = self.task_utils.curThread() 
        if cur_tid != self.tid:
            return
        addr = memory.logical_address
        if addr >= self.param.kernel_base:
            return
        sp = self.mem_utils.getRegValue(self.cpu, 'sp') 
        ''' TBD fix, pickle stack pointer recorded in genMonitor and use it!'''
        if addr > (sp-9000):
            return
        cpl = memUtils.getCPL(cpu)
        if cpl == 0:
            return
        size = memory.size
        #eip = self.mem_utils.getRegValue(self.cpu, 'pc') 
        #self.lgr.debug('trackFunctionWrite writeHap 0x%x length %d eip: 0x%x 0x%x' % (addr, size, eip, self.cpu.cycles))
        count = self.writeMarks.dataWrite(addr, size)
        if count > 200:
            self.funExitHap(None, None, None, None) 
        
    def blanketWrites(self):
        count = self.param.kernel_base
        self.lgr.debug('blanketWrites kernel_base 0x%x' % count)
        proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Write, 0, count, 0)
        self.write_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.writeHap, None, 
            proc_break, 'blanket_writes')

    def stopBlanket(self):
        self.context_manager.genDeleteHap(self.write_hap)
        self.write_hap = None

    def getWatchMarks(self):
        return self.writeMarks.getWatchMarks()

    def compareMarks(self):
        merged = {} 
        for mark in self.read_watch_marks:
            merged[mark['cycle']] = mark 
        for mark in self.writeMarks.getWatchMarks():
            merged[mark['cycle']] = mark 
        for cycle in sorted(merged):
            print('%s ip:0x%x  cycle:0x%x' % (merged[cycle]['msg'], merged[cycle]['ip'], merged[cycle]['cycle']))
          
    def mergeIntervals(self, intervals):
        sorted_by_lower_bound = sorted(intervals, key=lambda tup: tup[0])
        merged = []

        for higher in sorted_by_lower_bound:
            if not merged:
                print('not merged? eh? appending 0x%x-0x%x' % higher)
                merged.append(higher)
            else:
                lower = merged[-1]
                # test for intersection between lower and higher:
                # we know via sorting that lower[0] <= higher[0]
                if higher[0] <= lower[1]:
                    upper_bound = max(lower[1], higher[1])
                    print('replacing 0x%x-0x%x with 0x%x-0x%x' % (merged[-1][0], merged[-1][1], lower[0], upper_bound))
                    merged[-1] = (lower[0], upper_bound)  # replace by merged interval
                else:
                    print('higher[0] > lower[1] appending 0x%x-0x%x' % higher)
                    merged.append(higher)
        return merged

    def showWriteRanges(self):
        range_list = []

        for watch_mark in self.writeMarks.getWatchMarks():
            end = watch_mark['end']
            if end is not None: 
                item = (watch_mark['start'], watch_mark['end'])
                range_list.append(item)
            else:
                item = (watch_mark['start'], watch_mark['start']+watch_mark['size']-1)
                range_list.append(item)
        merged = self.mergeIntervals(range_list)
        #print('Write ranges of len >8')
        print('Write ranges  >8')
        for start,end in merged:
            print('0x%x - 0x%x len: %d' % (start, end, (end-start)+1))
            #if end > (start+8):
            #    print('0x%x - 0x%x' % (start, end))
        
        if len(merged) == 1:
            addr, end = merged[0]
            size = end - addr + 1
            self.lgr.debug('showWriteRanges addr 0x%x size %d' % (addr, size))
            byte_array = self.mem_utils.readBytes(self.cpu, addr, size)
            with open('/tmp/write_range.bin', 'w') as fh:
                fh.write(byte_array)
         
    def goToMark(self, index):
        retval = None
        cycle = self.writeMarks.getCycle(index)
        if cycle is not None:
            SIM_run_command('pselect %s' % self.cpu.name)
            SIM_run_command('skip-to cycle=%d' % cycle)
            retval = cycle
        else:
           self.lgr.error('No write mark with index %d' % index)
        return cycle
