from simics import *
import os
import pickle
import elfText
import resimUtils
import json
from pathlib import Path
from resimHaps import *
'''
Manage maps of shared object libraries
Also track text segment.
NOTE: does not catch introduction of new code other than so libraries
'''
class CodeSection():
    def __init__(self, addr, size, fname):
        self.addr = addr
        self.size = size
        self.fname = fname

class ProgInfo():
    def __init__(self, text_start, text_size, text_offset, local_path):
        self.text_start = text_start
        self.text_size = text_size
        if self.text_start is not None and text_size is not None:
           self.text_end = text_start + text_size
        self.text_offset = text_offset
        self.local_path = local_path

class LoadInfo():
    def __init__(self, addr, size):
        self.addr = addr
        self.size = size
        self.end = addr+size
    
class SOMap():
    def __init__(self, top, cell_name, cell, cpu, context_manager, task_utils, targetFS, run_from_snap, lgr):
        self.context_manager = context_manager
        self.task_utils = task_utils
        self.targetFS = targetFS
        self.cell_name = cell_name
        self.so_addr_map = {}
        self.so_file_map = {}
        self.lgr = lgr
        self.top = top
        self.cell = cell
        self.cpu = cpu

        # static data from elf headers
        self.prog_info = {}

        self.prog_start = {}
        self.prog_end = {}
        self.text_prog = {}
        self.prog_text_start = {}
        self.prog_text_end = {}
        self.prog_text_offset = {}
        self.prog_local_path = {}
        self.hap_list = []
        self.stop_hap = None
        self.fun_mgr = None
        if run_from_snap is not None:
            self.loadPickle(run_from_snap)
        # optimization?
        self.cheesy_tid = 0
        self.cheesy_mapped = 0
        self.fun_list_cache = []
        self.so_watch_callback = {}

        self.prog_base_map = {}


    def loadPickle(self, name):
        somap_file = os.path.join('./', name, self.cell_name, 'soMap.pickle')
        if os.path.isfile(somap_file):
            self.lgr.debug('SOMap pickle from %s' % somap_file)
            so_pickle = pickle.load( open(somap_file, 'rb') ) 
            #print('start %s' % str(so_pickle['text_start']))
            self.text_prog = so_pickle['text_prog']
            self.prog_start = so_pickle['prog_start']
            self.prog_end = so_pickle['prog_end']
            self.prog_local_path = so_pickle['prog_local_path']
            if 'prog_info' in so_pickle:
                self.so_addr_map = so_pickle['so_addr_map']
                self.so_file_map = so_pickle['so_file_map']
                self.prog_info = so_pickle['prog_info']
            else:
                # backward compatability, but only most recent
                for tid in self.text_prog:
                    prog = self.text_prog[tid]
                    if self.prog_start[tid] is not None:
                        size = self.prog_end[tid] - self.prog_start[tid]
                        if tid in self.prog_local_path:
                            self.prog_info[prog] = ProgInfo(self.prog_start[tid], size, 0, self.prog_local_path[tid])
                        else:
                            self.prog_info[prog] = ProgInfo(self.prog_start[tid], size, 0, None)
                    else:
                        self.prog_info[prog] = None
                old_so_file_map = so_pickle['so_file_map']
                for tid in old_so_file_map:
                    for text_seg in old_so_file_map[tid]:
                        prog = old_so_file_map[tid][text_seg]
                        if prog not in self.prog_info:
                            end = text_seg.text_start + text_seg.text_size - 1
                            self.prog_info[prog] = ProgInfo(text_seg.text_start, end, text_seg.text_offset, None)
                        self.lgr.debug('wtf %s text_seg.address 0x%x, offset 0x%x' % (prog, text_seg.address, text_seg.offset))
                        load_info = LoadInfo(text_seg.address, text_seg.size)
                        if tid not in self.so_file_map:
                            self.so_file_map[tid] = {}
                            self.so_addr_map[tid] = {}
                        self.so_file_map[tid][load_info] = prog
                        self.so_addr_map[tid][prog] = load_info.addr            

            '''            


            # backward compatability 
            if 'prog_start' in so_pickle:
                self.prog_start = so_pickle['prog_start']
                self.prog_end = so_pickle['prog_end']
                if 'prog_local_path' in so_pickle:
                    self.prog_local_path = so_pickle['prog_local_path']
            else:
                self.lgr.debug('soMap loadPickle old format, find text info')
                self.prog_start = so_pickle['text_start']
                self.prog_end = so_pickle['text_end']
                for tid in self.so_file_map:
                    if tid in self.text_prog:
                        full_path = self.targetFS.getFull(self.text_prog[tid], lgr=self.lgr)
                        self.lgr.debug('soMap loadPickle tid in text_prog %s full is %s' % (tid, full_path))
                        elf_info = elfText.getText(full_path, self.lgr)
                        if elf_info.text_start is not None:
                            self.prog_text_start[tid] = elf_info.text_start        
                            self.prog_text_end[tid] = elf_info.text_start + elf_info.text_size 
                            self.prog_text_offset[tid] = elf_info.text_offset        
                            break
            # really old backward compatibility 
            if self.prog_start is None:
                self.lgr.debug('soMap loadPickle text_start is none')
                self.prog_start = {}
                self.prog_end = {}
                self.text_prog = {}

            # pid to tid compatability
            add_so_addr_map = {}
            for pid in self.so_addr_map:
                if type(pid) is int:
                    add_so_addr_map[str(pid)] = self.so_addr_map[pid]
            for tid in add_so_addr_map:
                self.so_addr_map[tid] = add_so_addr_map[tid]

            add_so_file_map = {}
            for pid in self.so_file_map:
                if type(pid) is int:
                    add_so_file_map[str(pid)] = self.so_file_map[pid]

            for tid in add_so_file_map:
                self.so_file_map[tid] = add_so_file_map[tid]

            add_text_prog = {}
            for pid in self.text_prog:
                if type(pid) is int:
                    add_text_prog[str(pid)] = self.text_prog[pid]
            for tid in add_text_prog:
                self.text_prog[tid] = add_text_prog[tid]
            add_prog_start = {}
            for pid in self.prog_start:
                if type(pid) is int:
                    add_prog_start[str(pid)] = self.prog_start[pid]
            for tid in add_prog_start:
                self.prog_start[tid] = add_prog_start[tid]
            add_prog_end = {}
            for pid in self.prog_end:
                if type(pid) is int:
                    add_prog_end[str(pid)] = self.prog_end[pid]
            for tid in add_prog_end:
                self.prog_end[tid] = add_prog_end[tid]
            '''            
            self.lgr.debug('SOMap  loadPickle %d text_progs' % (len(self.text_prog)))

    def pickleit(self, name):
        somap_file = os.path.join('./', name, self.cell_name, 'soMap.pickle')
        so_pickle = {}
        so_pickle['so_addr_map'] = self.so_addr_map
        so_pickle['so_file_map'] = self.so_file_map
        so_pickle['prog_start'] = self.prog_start
        so_pickle['prog_end'] = self.prog_end
        so_pickle['text_prog'] = self.text_prog
        so_pickle['prog_local_path'] = self.prog_local_path
        so_pickle['prog_info'] = self.prog_info
        fd = open( somap_file, "wb") 
        pickle.dump( so_pickle, fd)
        self.lgr.debug('SOMap pickleit to %s saved %d text_progs ' % (somap_file, len(self.text_prog)))

    def isCode(self, address, tid):
        ''' is the given address within the text segment or those of SO libraries? '''
        #self.lgr.debug('compare 0x%x to 0x%x - 0x%x' % (address, self.prog_start, self.prog_end))
        tid = self.getSOTid(tid)
        if tid is None:
            cpu, comm, tid = self.task_utils.curThread() 
            #self.lgr.debug('SOMap isCode, regot tid after getSOTid failed, tid:%s missing from so_file_map' % tid)
            return False
        if tid in self.prog_start and self.prog_start[tid] is not None and address >= self.prog_start[tid] and address <= self.prog_end[tid]:
            return True
        if tid not in self.so_file_map:
            tid = self.task_utils.getCurrentThreadLeaderTid()
        if tid not in self.so_file_map:
            #self.lgr.debug('SOMap isCode, tid:%s missing from so_file_map' % tid)
            return False
        for load_info in self.so_file_map[tid]:
            start = load_info.addr 
            end = load_info.end
            if address >= start and address <= end:
                return True
        return False

    def isAboveLibc(self, address):
        retval = False
        if self.isMainText(address):
            retval = True
        else:
            so_file = self.getSOFile(address)
            if so_file is not None and not resimUtils.isClib(so_file):
                fun = self.fun_mgr.getFunName(address)
                if fun is not None:
                    retval = True 
        return retval           

    def isMainText(self, address):
        cpu, comm, tid = self.task_utils.curThread() 
        tid = self.getSOTid(tid)
        if tid is None:
            return False
        if tid in self.prog_start and self.prog_start[tid] is not None:
            if address >= self.prog_start[tid] and address <= self.prog_end[tid]:
                return True
            else: 
                return False
        else: 
            return False

    def swapTid(self, old, new):
        ''' intended for when original process exits following a fork '''
        ''' TBD, half-assed logic for deciding if procs were all really deleted '''
        retval = True
        if old in self.prog_start:
            self.prog_start[new] = self.prog_start[old]
            self.prog_end[new] = self.prog_end[old]
            self.text_prog[new] = self.text_prog[old]
            if old in self.so_addr_map:
                self.so_addr_map[new] = self.so_addr_map[old]
                self.so_file_map[new] = self.so_file_map[old]
            else:
                self.lgr.debug('soMap swaptid tid:%s not in so_addr_map' % old)
        else:
            self.lgr.debug('soMap swaptid tid:%s not in text_start' % old)
            retval = False
        return retval

    def addText(self, path, prog, tid_in):
        tid_already = self.getSOTid(tid_in)
        if tid_already != tid_in:
            self.lgr.debug('soMap addText tid_in %s is thread of existing leader %s' % (tid_in, tid_alread))
            return None
        self.lgr.debug('soMap addText tid %s path %s' % (tid_in, path))
        # Add information about a newly loaded program, returning load info
        retval = None
        prog_basename = os.path.basename(path)
        if prog_basename == 'busybox':
            self.lgr.debug('soMap ignore busybox')
            return None
        if prog_basename not in self.prog_base_map:
            self.prog_base_map[prog_basename] = prog
        else:
            if self.prog_base_map[prog_basename] != prog:
                self.lgr.warning('soMap addText collision on program base name %s adding %s, replace old with new' % (prog_basename, prog))
                self.prog_base_map[prog_basename] = prog
        if prog not in self.prog_info:
            elf_info = elfText.getText(path, self.lgr)
            if elf_info is not None:
                self.prog_info[prog] = ProgInfo(elf_info.text_start, elf_info.size, elf_info.offset, path)
            else:
                self.lgr.debug('soMap addText no elf info for %s' % path)
                pass
        if tid_in is not None:
            tid = tid_in
        else: 
            tid = self.getThreadTid(tid_in, quiet=True)
        if tid not in self.so_addr_map:    
            self.so_addr_map[tid] = {}
            self.so_file_map[tid] = {}
            self.lgr.debug('soMap addText tid:%s added to so_file_map' % tid)
        else:
            self.lgr.debug('soMap addText tid:%s already in map len of so_addr_map %d' % (tid, len(self.so_file_map)))
        if tid in self.prog_start:
            self.lgr.debug('soMap addText tid:%s already in prog_start as %s, overwrite' % (tid, self.text_prog[tid]))
        
        if prog in self.prog_info:    
            # TBD until we can get load address from process info, assume no ASLR
            load_addr = self.prog_info[prog].text_start
            self.prog_start[tid] = load_addr
            self.prog_end[tid] = self.prog_info[prog].text_end
            self.text_prog[tid] = prog
            self.checkSOWatch(load_addr, prog)
            size = self.prog_info[prog].text_end - self.prog_start[tid]
            retval = LoadInfo(load_addr, size)
        return retval

    def noText(self, prog, tid):
        self.lgr.debug('soMap noText, prog %s tid:%s' % (prog, tid))
        self.text_prog[tid] = prog
        self.prog_start[tid] = None
        self.prog_end[tid] = None

    def getAnalysisPath(self, fname):
        root_prefix = self.top.getCompDict(self.cell_name, 'RESIM_ROOT_PREFIX')
        return resimUtils.getAnalysisPath(None, fname, fun_list_cache = self.fun_list_cache, root_prefix=root_prefix, lgr=self.lgr)
            
    def setFunMgr(self, fun_mgr, tid_in):
        if fun_mgr is None:
            self.lgr.warning('soMap setFunMgr input fun_mgr is none')
            return
        self.fun_mgr = fun_mgr
        tid = self.getThreadTid(tid_in, quiet=True)
        if tid is None:
            self.lgr.error('soMap setFunMgr failed to getThreadTid, tid_in was %s' % tid_in)
            return
        sort_map = {}
        for load_info in self.so_file_map[tid]:
            sort_map[load_info.addr] = load_info

        for locate in sorted(sort_map, reverse=True):
            load_info = sort_map[locate]
            fpath = self.so_file_map[tid][load_info]
            full_path = self.getAnalysisPath(fpath)
            # TBD can we finally get rid of old style paths?
            #if full_path is None:
            #    full_path = self.targetFS.getFull(fpath, lgr=self.lgr)
            if full_path is not None:
                full_path = full_path+'.funs'
                self.fun_mgr.add(full_path, locate)
            
    def addSO(self, tid_in, prog, addr, count):
        if '..' in prog:
            prog = Path(prog).resolve()
        prog_basename = os.path.basename(prog)
        if prog_basename not in self.prog_base_map:
            self.prog_base_map[prog_basename] = prog
        else:
            if self.prog_base_map[prog_basename] != prog:
                self.lgr.warning('soMap addeSO collision on program base name %s adding %s.  Replace old with new.' % (prog_basename, prog))
                self.prog_base_map[prog_basename] = prog
        tid = self.getThreadTid(tid_in, quiet=True)
        if tid is None:
            tid = tid_in
        if tid in self.so_addr_map and prog in self.so_addr_map[tid]:
            ''' multiple mmap calls for one so file.  assume continguous and adjust
                address to lowest '''
            if self.so_addr_map[tid][prog].addr> addr:
                self.so_addr_map[tid][prog].addr = addr
                # TBD?
                #if self.ida_funs is not None:
                #    self.ida_funs.adjust(full_path, addr))
        else:
            if tid not in self.so_addr_map:
                self.so_addr_map[tid] = {}
                self.so_file_map[tid] = {}

            full_path = self.targetFS.getFull(prog, lgr=self.lgr)
            if prog not in self.prog_info:
                elf_info = elfText.getText(full_path, self.lgr)
                if elf_info is not None:
                    self.prog_info[prog] = ProgInfo(elf_info.text_start, elf_info.size, elf_info.offset, full_path)
                else:
                    self.lgr.debug('soMap addSo no elf info from %s' % prog)

            load_info = LoadInfo(addr, count)

            self.so_addr_map[tid][prog] = load_info
            self.so_file_map[tid][load_info] = prog
            self.lgr.debug('soMap addSO tid: %s prog %s addr: 0x%x' % (tid, prog, addr))

            if self.fun_mgr is not None:
                self.fun_mgr.add(full_path, addr)

            self.checkSOWatch(addr, prog)

    def listSO(self, filter=None):
        for tid in self.so_file_map:
            for load_info in self.so_file_map[tid]:
                prog = self.so_file_map[tid][load_info]
                if filter is None or filter in prog:
                    print('tid:%s  0x%x - 0x%x   %s' % (tid, load_info.addr, load_info.end, prog))
        for tid in self.text_prog:
            if filter is None or filter in self.text_prog[tid]:
                if tid in self.prog_start and self.prog_start[tid] is not None:
                    print('tid:%s  0x%x - 0x%x   %s' % (tid, self.prog_start[tid], self.prog_end[tid], self.text_prog[tid]))
                else:
                    #print('tid:%s  no text found' % tid)
                    pass
          
    def showSO(self, tid=None, filter=None):
        if tid is None:
            cpu, comm, tid = self.task_utils.curThread() 
        tid = self.getSOTid(tid)
        if tid is None:
            cpu, comm, tid = self.task_utils.curThread() 
            print('no so map for %s' % tid)
        print('SO Map for threads led by group leader tid: %s' % tid)
        if tid in self.so_file_map:
            if tid in self.prog_start and self.prog_start[tid] is not None:
                print('0x%x - 0x%x   %s' % (self.prog_start[tid], self.prog_end[tid], self.text_prog[tid]))
            else:
                print('tid:%s not in text sections' % tid)
                self.lgr.debug('tid:%s not in text sections' % tid)
            sort_map = {}
            for load_info in self.so_file_map[tid]:
                prog = self.so_file_map[tid][load_info]
                load_addr = load_info.addr
                sort_map[load_addr] = load_info
                
            for locate in sorted(sort_map):
                load_info = sort_map[locate]
                prog = self.so_file_map[tid][load_info]
                if filter is None or filter in prog:
                    if prog in self.prog_info: 
                        print('0x%x - 0x%x 0x%x 0x%x  %s' % (locate, load_info.end, self.prog_info[prog].text_offset, self.prog_info[prog].text_size, prog))
                    else:
                        print('0x%x - 0x%x ???  ???   %s' % (locate, load_info.end, prog))
        else:
            print('no so map for %s' % tid)
            
    def getSO(self, tid=None, quiet=False):
        retval = {}
        if tid is None:
            cpu, comm, tid = self.task_utils.curThread() 
        tid = self.getSOTid(tid)
        if tid is None:
            cpu, comm, tid = self.task_utils.curThread() 
        retval['group_leader'] = tid
        if tid in self.so_file_map:
            if tid in self.prog_start and self.prog_start[tid] is not None:
                retval['prog_start'] = self.prog_start[tid]
                retval['prog_end'] = self.prog_end[tid]
                retval['prog'] = self.text_prog[tid]
                if tid in self.prog_local_path:
                    retval['prog_local_path'] = self.prog_local_path[tid]
                else:
                    retval['prog_local_path'] = self.top.getFullPath()
            else:
                self.lgr.debug('tid:%s not in text sections' % tid)
            sort_map = {}
            for load_info in self.so_file_map[tid]:
                sort_map[load_info.addr] = load_info
            retval['sections'] = []
            for locate in sorted(sort_map):
                section = {}
                load_info = sort_map[locate]
                prog = self.so_file_map[tid][load_info]
                section['locate'] = locate
                section['end'] = load_info.end
                if prog in self.prog_info:
                    section['offset'] = self.prog_info[prog].text_offset
                    section['size'] = self.prog_info[prog].text_size
                else:
                    section['offset'] = 0
                    section['size'] = 0
                section['file'] = prog
                retval['sections'].append(section)
        else:
            self.lgr.debug('no so map for %s' % tid)
        ret_json = json.dumps(retval) 
        if not quiet:
            print(ret_json)
        return ret_json
 
    def handleExit(self, tid, killed=False):
        ''' when a thread leader exits, clone the so map structures to each child, TBD determine new thread leader? '''
        if tid not in self.so_addr_map and tid not in self.prog_start:
            self.lgr.debug('SOMap handleExit tid:%s not in so_addr map' % tid)
            return
        self.lgr.debug('SOMap handleExit tid:%s' % tid)
        if not killed:
            tid_list = self.context_manager.getThreadTids()
            if tid in tid_list:
                self.lgr.debug('SOMap handleExit tid:%s in tidlist' % tid)
                for ttid in tid_list:
                    if ttid != tid:
                        self.lgr.debug('SOMap handleExit new tid:%s added to SOmap' % ttid)
                        if tid in self.so_addr_map:
                            self.so_addr_map[ttid] = self.so_addr_map[tid]
                            self.so_file_map[ttid] = self.so_file_map[tid]
                        if tid in self.prog_start and self.prog_start[tid] is not None:
                            self.prog_start[ttid] = self.prog_start[tid]
                            self.prog_end[ttid] = self.prog_end[tid]
                            self.text_prog[ttid] = self.text_prog[tid]
                        else:
                            self.lgr.debug('SOMap handle exit, missing text_start entry tid: %s ttid:%s' % (tid, ttid))
        
            else:
                self.lgr.debug('SOMap handleExit tid:%s NOT in tidlist' % tid)
        if tid in self.so_addr_map:
            del self.so_addr_map[tid]
            del self.so_file_map[tid]
        if tid in self.prog_start:
           del self.prog_start[tid]
           del self.prog_end[tid]
           del self.text_prog[tid]


    def getThreadTid(self, tid, quiet=False):
        if tid in self.so_file_map:
            return tid
        else:
            tid_list = self.context_manager.getThreadTids()
            if tid not in tid_list:
                #self.lgr.debug('SOMap getThreadTid requested unknown tid:%s %s  -- not debugging?' % (tid, str(tid_list)))
                return None
            else:
                for p in tid_list:
                    if p in self.so_file_map:
                        return p
        if not quiet:
            self.lgr.error('SOMap getThreadTid requested unknown tid:%s' % tid)
        #else:
        #    self.lgr.debug('SOMap getThreadTid requested unknown tid:%s' % tid)
        return None
 
    def getSOTid(self, tid):
        # all threads in a family share one record for what we think is the parent tid
        retval = tid
        if tid not in self.so_file_map:
            if tid == self.cheesy_tid:
                return self.cheesy_mapped
            ptid = self.task_utils.getGroupLeaderTid(tid)
            self.lgr.debug('SOMap getSOTid getCurrnetTaskLeader got %s for current tid:%s' % (ptid, tid))
            if ptid != tid:
                self.lgr.debug('SOMap getSOTid use group leader')
                retval = ptid
            else:
                ptid = self.task_utils.getTidParent(tid)
                if ptid != tid:
                    self.lgr.debug('SOMap getSOTid use parent %s' % ptid)
                    retval = ptid
                else:
                    self.lgr.debug('getSOTid no so map after get parent for %s' % tid)
                    retval = None
            self.cheesy_tid = tid
            self.cheesy_mapped = retval
        return retval

    def getSOFile(self, addr_in):
        #if addr_in is not None:
        #    self.lgr.debug('getSOFile addr_in 0x%x' % addr_in)
        #else:
        #    self.lgr.debug('getSOFile addr_in is None')
        if addr_in is None:
            #self.lgr.debug('getSOFile called with None')
            return None
        retval = None
        #tid = self.getThreadTid(tid_in)
        #if tid is None:
        #    self.lgr.error('getSOFile, no such tid in threads %d' % tid_in)
        #    return
        #self.lgr.debug('getSOFile for tid:%s addr 0x%x' % (tid, addr_in))
        cpu, comm, tid = self.task_utils.curThread() 
        tid = self.getSOTid(tid)
        if tid is None:
            return None
        if tid in self.so_file_map:
            if tid not in self.prog_start or self.prog_start[tid] is None:
                self.lgr.warning('SOMap getSOFile tid:%s in so_file map but not prog_start' % tid)
                return None
            if self.prog_end[tid] is None:
                self.lgr.warning('SOMap getSOFile tid:%s in so_file map but None for prog_end' % tid)
                return None
            if addr_in >= self.prog_start[tid] and addr_in <= self.prog_end[tid]:
                retval = self.text_prog[tid]
            else:
                #for text_seg in sorted(self.so_file_map[tid]):
                for load_addr in self.so_file_map[tid]:
                    start = load_addr.addr 
                    end = load_addr.end
                    if start <= addr_in and addr_in <= end:
                        retval = self.so_file_map[tid][load_addr]
                        break
            
        else:
            self.lgr.debug('getSOFile no so map for %s' % tid)
        #self.lgr.debug('getSOFile returning %s' % retval)
        return retval

    def getProg(self, tid):
        retval = None
        tid = self.getSOTid(tid)
        if tid in self.text_prog:
            retval = self.text_prog[tid]
        return retval

    def getSOInfo(self, addr_in):
        retval = None, None, None
        cpu, comm, tid = self.task_utils.curThread() 
        tid = self.getSOTid(tid)
        if tid is None:
            return retval
        if tid in self.so_file_map:
            if tid in self.prog_start and self.prog_start[tid] is not None and addr_in >= self.prog_start[tid] and addr_in <= self.prog_end[tid]:
                retval = self.text_prog[tid], self.prog_start[tid], self.prog_end[tid]
            else:
                for load_addr in self.so_file_map[tid]:
                    #start = text_seg.locate + text_seg.offset
                    start = load_addr.addr 
                    end = load_addr.end
                    if start <= addr_in and addr_in <= end:
                        retval = self.so_file_map[tid][load_addr], start, end
                        break
            
        else:
            self.lgr.debug('getSOInfo no so map for %s' % tid)
        return retval


    def stopHap(self, cpu, one, exception, error_string):
        if self.stop_hap is not None:
            eip = self.top.getEIP(cpu)
            self.lgr.debug('soMap stopHap ip: 0x%x' % eip)
            self.top.skipAndMail()
            RES_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None

    def stopAlone(self, cpu):
        if len(self.hap_list) > 0:
            self.stop_hap = RES_hap_add_callback("Core_Simulation_Stopped", 
            	     self.stopHap, cpu)
            self.lgr.debug('soMap stopAlone')
            for hap in self.hap_list:
                self.context_manager.genDeleteHap(hap)
            del self.hap_list[:]

            SIM_break_simulation('soMap')

    def knownHap(self, tid, third, forth, memory):
        if len(self.hap_list) > 0:
            cpu, comm, cur_tid = self.task_utils.curThread() 
            if tid == cur_tid: 
                value = memory.logical_address
                fname, start, end = self.getSOInfo(value)
                if fname is not None and start is not None:
                    self.lgr.debug('soMap knownHap tid:%s memory 0x%x %s start:0x%x end:0x%x' % (tid, value, fname, start, end))
                else:
                    self.lgr.debug('soMap knownHap tid:%s memory 0x%x NO mapping file %s' % (tid, value, fname))

                SIM_run_alone(self.stopAlone, cpu)                
            #else:
            #    self.lgr.debug('soMap knownHap wrong tid, wanted %s got %s' % (tid, cur_tid))
        
    def runToKnown(self, skip=None):        
       cpu, comm, cur_tid = self.task_utils.curThread() 
       map_tid = self.getSOTid(cur_tid)
       if map_tid in self.prog_start: 
           start =  self.prog_start[map_tid] 
           length = self.prog_end[map_tid] - self.prog_start[map_tid] 
           proc_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, start, length, 0)
           self.hap_list.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.knownHap, cur_tid, proc_break, 'runToKnown'))
           #self.lgr.debug('soMap runToKnow text 0x%x 0x%x' % (start, length))
       else:
           self.lgr.debug('soMap runToKnown no text for %s' % map_tid)
       if map_tid in self.so_file_map:
            for load_info in self.so_file_map[map_tid]:
                start = load_info.addr
                length = load_info.size
                end = load_info.end
                if skip is None or not (skip >= start and skip <= end):
                    proc_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, start, length, 0)
                    self.hap_list.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.knownHap, cur_tid, proc_break, 'runToKnown'))
                else:
                    self.lgr.debug('soMap runToKnow, skip %s' % (self.so_file_map[map_tid][load_info]))
                #self.lgr.debug('soMap runToKnow lib %s 0x%x 0x%x' % (self.so_file_map[map_tid][text_seg], start, length))
       else:
           self.lgr.debug('soMap runToKnown no so_file_map for %s' % map_tid)
       if len(self.hap_list) > 0:  
           return True
       else:
           return False

    def wordSize(self, tid):
       # TBD why take tid as param?
       return self.task_utils.getMemUtils().wordSize(self.cpu)

    def getMachineSize(self, tid):
       ws = self.task_utils.getMemUtils().wordSize(self.cpu)
       if ws == 4:
           return 32
       else:
           return 64

    def getFullPath(self, comm):
        retval = None
        for pid in self.text_prog:
            base = os.path.basename(self.text_prog[pid])
            if base.startswith(comm):
                retval = self.text_prog[pid]
        return retval

    def getLocalPath(self, tid):
        tid = self.getSOTid(tid)
        retval = None
        if tid in self.prog_local_path:
            retval = self.prog_local_path[tid]
        return retval

    def getLoadAddr(self, in_fname, tid=None):
        #self.lgr.debug('mapSO loadAddr %s tid %s' % (in_fname, tid))
        retval = None
        prog = self.fullProg(in_fname)
        if tid is None:
            cpu, comm, tid = self.task_utils.curThread() 
        map_tid = self.getSOTid(tid)
        if map_tid not in self.so_file_map:
            self.lgr.error('soMap getLoadAddr tid %s not in so_file_map' % map_tid)
        else:
            for load_info in self.so_file_map[map_tid]:
                #self.lgr.debug('winDLLMap compare %s to %s' % (os.path.basename(prog).lower(), ntpath.basename(section.fname).lower()))
                if os.path.basename(self.so_file_map[map_tid][load_info]) == os.path.basename(prog):
                    retval = load_info.addr
                    self.lgr.debug('mapSO got match for %s address 0x%x tid:%s' % (prog, retval, tid))
                    break 

        if retval is None and map_tid in self.text_prog:
            if os.path.basename(self.text_prog[map_tid]) == os.path.basename(prog):
                retval = self.prog_start[map_tid]
        return retval

    def getImageBase(self, in_fname):
        prog = self.fullProg(in_fname)
        retval = None
        if prog in self.prog_info:
            retval = self.prog_info[prog].text_start
        else:
            self.lgr.debug('soMap getImageBase not in prog_info: %s' % prog)

        return retval

    def getSOPidList(self, in_fname):
        # Get a list of PIDs that have the given library loaded
        retval = []
        prog = self.fullProg(in_fname)
        self.lgr.debug('soMap getSOPidList prog %s' % prog)
        for tid in self.so_file_map:
            for load_addr in self.so_file_map[tid]:
                if os.path.basename(self.so_file_map[tid][load_addr]) == os.path.basename(prog):
                    retval.append(tid) 
        for tid in self.text_prog: 
            if os.path.basename(self.text_prog[tid]) == os.path.basename(prog):
                retval.append(tid) 
        return retval

    def addSOWatch(self, fname, callback, name=None):
        if name is None:
            name = 'NONE'
        prog = self.fullProg(in_fname)
        if prog not in self.so_watch_callback:
            self.so_watch_callback[prog] = {}
        self.so_watch_callback[prog][name] = callback

    def cancelSOWatch(self, fname, name):
        prog = self.fullProg(in_fname)
        if prog in self.so_watch_callback:
            if name in self.so_watch_callback[prog]:
                del self.so_watch_callback[prog][name]

    def checkSOWatch(self, load_addr, fpath):
        if fpath in self.so_watch_callback:
            for name in self.so_watch_callback[fpath]:
                if name == 'NONE':
                    self.lgr.error('soMap checkSOWatch do callback for %s but name is NONE????' % fpath)
                else:
                    # pass the load address to the callback
                    self.lgr.debug('soMap checkSOWatch do callback for %s, name %s' % (fpath, name))
                    self.so_watch_callback[fpath][name](load_addr, name)

    def getLoadInfo(self):
        load_info = None
        cpu, comm, tid = self.task_utils.curThread() 
        if tid in self.prog_start:
            size = self.prog_end[tid] - self.prog_start[tid] + 1 
            load_info = LoadInfo(self.prog_start[tid], size)
        return load_info

    def fullProg(self, prog_in):
        # if the given prog_in is a basename, use a prog_base_map to return the full path
        if '/' not in prog_in:
            if prog_in in self.prog_base_map:
                prog = self.prog_base_map[prog_in] 
            else:
                self.lgr.error('soMap fullProg called for %s, but not in prog_base_map' % prog_in)
        else:
            prog = prog_in
        return prog

    def getLoadOffset(self, prog_in, tid=None):
        retval = None
        prog = self.fullProg(prog_in)
        if tid is None:
            cpu, comm, tid = self.task_utils.curThread() 
        tid = self.getSOTid(tid)
        if tid in self.prog_start:
            load_addr = self.prog_start[tid]
            if prog in self.prog_info:
                image_base =  self.prog_info[prog].text_start
                retval = load_addr - image_base
            else:
                self.lgr.error('soMap getLoadOffset prog %s not in prog_info' % prog)
        else:
            retval = self.getLoadAddr(prog, tid)
        return retval

    def getCodeSections(self, tid):
        retval = []
        tid = self.getSOTid(tid)
        if tid in self.so_file_map: 
            for load_info in self.so_file_map[map_tid]:
                code_section = CodeSection(load_info.addr, load_info.size, self.so_file_map[map_tid][load_info])
                retval.append(code_section) 
        return retval
