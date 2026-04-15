#!/usr/bin/env python3
#
# 
# diff 2 log files
#
import sys
import os
import argparse
import re
def rmTid(line):
    pattern = r'tid:\d+\s'
    retval = re.sub(pattern, '', line)
    return retval

def rmParam(line):
    pattern = r'param\d:0x[0-9a-fA-F]+\s'
    retval = re.sub(pattern, '', line)
    return retval

def rmHex(line):
    pattern = r'\s+0x[0-9a-fA-F]+\s'
    retval = re.sub(pattern, '', line)
    return retval

def rmCycle(line):
    pattern = r'cycle:0x[0-9a-fA-F]+$'
    retval = re.sub(pattern, '', line)
    return retval

def rmData(line):
    pattern = r' data:.*'
    retval = re.sub(pattern, '', line)
    return retval

def getNextLine(fh, tid, hex, data):
    retval = None
    line = None
    while True:
        line = fh.readline().decode()
        if tid:
            line = rmTid(line)
        if data:
            line = rmData(line)
        if hex:
            line = rmHex(line)
            line = rmParam(line)
        line = rmCycle(line)
        if line is None or len(line) == 0:
            break
        elif len(line.strip()) == 0:
            continue
        elif line[0] == ' ' or ord(line[0]) == 9:
            continue
        elif 'object at 0x' in line:
            continue
        elif 'magicHap' in line:
            continue
        elif 'Hap wrong process' in line:
            continue
        elif '--access' in line:
            continue
        elif '--mmap' in line:
            continue
        elif '--' in line:
            retval = line.split('--', 1)[1] 
            break
        else:
            print('confused %s' % line)
            continue
    return retval, line

def showDiff(line1, line2):
   if len(line1) != len(line2):
       print('Lengths differ, line1 is %d and other is %d' % (len(line1), len(line2)))
   else:
       for i in range(len(line1)):
           if line1[i] != line2[i]:
               print('value at position %d, [%s] vs [%s]' % (i, line1[i], line2[i]))

parser = argparse.ArgumentParser(prog='dataDiff', description='Diff two RESim syscall logs')
parser.add_argument('f1', action='store', help='The first log')
parser.add_argument('f2', action='store', help='The 2nd log')
parser.add_argument('-t', '--ignore_tid', action='store_true', help='Ignore changes in tid value.')
parser.add_argument('-H', '--ignore_hex', action='store_true', help='Ignore changes in hex values.')
parser.add_argument('-d', '--ignore_data', action='store_true', help='Ignore changes in input/output data values.')
args = parser.parse_args()

logs1 = open(args.f1, 'rb')
logs2 = open(args.f2, 'rb')

while True:
    line1, orig1 = getNextLine(logs1, args.ignore_tid, args.ignore_hex, args.ignore_data)
    if line1 is None:
        print('%s eof' % f1)
        break
    line2, orig2 = getNextLine(logs2, args.ignore_tid, args.ignore_hex, args.ignore_data)
    if line2 is None:
        print('%s eof' % f2)
        break

    if line1 != line2:
        print('difference') 
        print('DIFF line1 %s' % orig1)
        print('DIFF line2 %s' % orig2)
        showDiff(line1, line2)
        #break
    else:
        print('line1 %s' % orig1)
        print('line2 %s' % orig2)
