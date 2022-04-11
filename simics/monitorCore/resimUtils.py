import os
import time
import logging
import subprocess
try:
    import cli
    from simics import *
except:
    ''' Not always called from simics context '''
    pass
def getLogger(name, logdir, level=None):
    os.umask(000)
    try:
        os.makedirs(logdir)
    except:
        pass
    lgr = logging.getLogger(name)
    #lhStdout = lgr.handlers[0]
    lgr.setLevel(logging.DEBUG)
    fh = logging.FileHandler(logdir+'/%s.log' % name)
    fh.setLevel(logging.DEBUG)
    frmt = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    fh.setFormatter(frmt)
    lgr.addHandler(fh)
    #lgr.removeHandler(lhStdout)
    lgr.info('Start of log from %s.py' % name)
    ch = logging.StreamHandler()
    ch.setLevel(logging.ERROR)
    ch.setFormatter(frmt)
    lgr.addHandler(ch)
    #lgr.propogate = False
    return lgr

def rprint(string):
    rl = SIM_get_object('RESim_log')
    SIM_log_info(1, rl, 0, string)

def reverseEnabled():
        cmd = 'sim.status'
        #cmd = 'sim.info.status'
        dumb, ret = cli.quiet_run_command(cmd)
        rev = ret.find('Reverse Execution')
        after = ret[rev:]
        parts = after.split(':', 1)
        if parts[1].strip().startswith('Enabled'):
            return True
        else:
            return False

def skipToTest(cpu, cycle, lgr):
        limit=100
        count = 0
        while SIM_simics_is_running() and count<limit:
            lgr.error('skipToTest but simics running')
            time.sleep(1)
            count = count+1
                
        if count >= limit:
            return False
        if not reverseEnabled():
            lgr.error('Reverse execution is disabled.')
            return False
        retval = True
        cli.quiet_run_command('pselect %s' % cpu.name)
        cmd = 'skip-to cycle = %d ' % cycle
        cli.quiet_run_command(cmd)
        #cli.quiet_run_command('si')
        #cli.quiet_run_command(cmd)
        
        now = cpu.cycles
        if now != cycle:
            lgr.error('skipToTest failed wanted 0x%x got 0x%x' % (cycle, now))
            time.sleep(1)
            cli.quiet_run_command(cmd)
            now = cpu.cycles
            if now != cycle:
                lgr.error('skipToTest failed again wanted 0x%x got 0x%x' % (cycle, now))
                retval = False
        return retval

def getFree():
    cmd = "free"
    ps = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = ps.communicate()
    use_available = False
    for line in output[0].decode("utf-8").splitlines():
         if 'available' in line:
             use_available = True
         if line.startswith('Mem:'):
             parts = line.split()
             tot = int(parts[1])
             if use_available:
                 free = int(parts[6])
             else:
                 free = int(parts[3])
             #print('tot %s   free %s' % (tot, free))             
             percent = (free / tot) * 100
             return int(percent)
    return None

def isParallel():
    ''' Determine if the current workspace is a parallel clone '''
    here = os.getcwd()
    ws = os.path.basename(here)
    if ws.startswith('resim_') and os.path.exists('resim_ctl.fifo'):
        return True
    else:
        return False

def getIdaData(full_path):
    retval = None
    resim_ida_data = os.getenv('RESIM_IDA_DATA')
    if resim_ida_data is None:
        print('ERROR: RESIM_IDA_DATA not defined')
    else: 
        base = os.path.basename(full_path)
        retval = os.path.join(resim_ida_data, base, base)
    return retval

def getProgPath(prog):
    ida_path = getIdaData(prog)
    data_path = ida_path+'.prog'
    prog_file = None
    with open(data_path) as fh:
        lines = fh.read().strip().splitlines()
        prog_file = lines[0].strip()
    return prog_file
