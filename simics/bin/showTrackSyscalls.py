#!/usr/bin/env python3
'''
Shows kernel call numbers for kernel watch marks.
Intended for use in determining if input data used in mkdir, open or create...
'''
import sys
import os
import glob
import json
import argparse
try:
    import ConfigParser
except:
    import configparser as ConfigParser
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import aflPath
import syscallNumbers
import resimUtils

def main():
    parser = argparse.ArgumentParser(prog='showTrackSyscalls', description='Show kernel call numbers from watch marks, e.g., to see if any input data is used in a create')
    parser.add_argument('ini', action='store', help='The ini file')
    parser.add_argument('target', action='store', help='The target')
    parser.add_argument('-c', '--call', action='store', help='Optional system call name.  If given, will display each queue file that reaches that call.')
    args = parser.parse_args()
    flist = aflPath.getAFLTrackList(args.target)
    call_list = []
    unistd = resimUtils.getIniTargetValue(args.ini, 'RESIM_UNISTD')
    syscalls = syscallNumbers.SyscallNumbers(unistd, None)
    print('unistd is %s' % unistd)
    if args.call is not None:
        show_call_num = syscalls.callnums[args.call]
        print('Will display queue files having watchmarks for system call %s (%d)' % (args.call, show_call_num))
    else:
        show_call_num = None
    for track in flist:
        #print('track: %s' % track)
        if not os.path.isfile(track):
            continue
        try:
            jtrack = json.load(open(track))
        except:
            continue
        mark_list = jtrack['marks']
        for mark in mark_list:
            if mark['mark_type'] == 'kernel':
                call_num = mark['callnum']
                if call_num not in call_list:
                    call_list.append(call_num)
                if show_call_num is not None and show_call_num == call_num:
                    print('%s' % track)
    for call in call_list:
        call_name = syscalls.syscalls[call]
        print('call %d  name: %s' % (call, call_name))
         

if __name__ == '__main__':
    sys.exit(main())
