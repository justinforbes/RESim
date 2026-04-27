#!/usr/bin/env python3
#
#
'''
Dump track files for a given target
'''
import sys
import os
import glob
import json
from collections import OrderedDict
import argparse
splits = {}
def getTrack(f):
    base = os.path.basename(f)
    cover = os.path.dirname(f)
    track = os.path.join(os.path.dirname(cover), 'trackio', base)
    return track

def showTrack(f):
    track_path = getTrack(f)
    if os.path.isfile(track_path):
        track = json.load(open(track_path))
        mark_list = track['marks']
        sorted_marks = sorted(mark_list, key=lambda x: x['cycle'])
        first = sorted_marks[0]
        print('first cycle of %s is is 0x%x' % (os.path.basename(f), first['cycle']))
        for mark in sorted_marks:
            if 'addr' not in mark:
                if 'src' in mark:
                    mark['addr'] = mark['src']
                elif 'start' in mark:
                    mark['addr'] = mark['start']
                elif 'ours' in mark:
                    mark['addr'] = mark['ours']
                elif 'recv_addr' in mark:
                    mark['addr'] = mark['recv_addr']
            if 'compare' not in mark:
                mark['compare'] = ''
            try:
                print('%d 0x%016x \t%10s \t0x%016x \t%30s \t0x%x' % (mark['index'], mark['ip'], mark['mark_type'], mark['addr'], mark['compare'].strip(), mark['cycle']))
            except:
                print('could not print %s' % str(mark))
    else:
        print('No file found at %s' % track_path)

def main():
    parser = argparse.ArgumentParser(prog='showTrack', description='dump track files')
    parser.add_argument('target', action='store', help='The AFL target, generally the name of the workspace.')
    args = parser.parse_args()
    print('showTrack begin')
    if args.target.endswith('/'):
        args.target = args.target[:-1]
    if os.path.isfile(args.target):
        print('showTrack for single file %s' % args.target)
        showTrack(args.target)
    else:
        afl_path = os.getenv('AFL_DATA')
        target_path = os.path.join(afl_path, 'output', args.target) 
        unique_path = os.path.join(target_path, args.target+'.unique')
        expaths = json.load(open(unique_path))
        print('got %d paths' % len(expaths))
        for index in range(len(expaths)):
            path = os.path.join(target_path, expaths[index])
            showTrack(path)

if __name__ == '__main__':
    sys.exit(main())
