#!/usr/bin/env python3
import pefile
import json
import sys
'''
Generate a json map of system call numbers to syscall names from the ntdll.dll for 
windows XP.
'''
def get_syscall_map(dll_path):
    """
    Creates a map of syscall numbers to function names by sorting ntdll exports by address.
    """
    print('dll_path is %s' % dll_path)
    ntdll = pefile.PE(dll_path)
    syscalls = []

    for exp in ntdll.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name and exp.name.startswith(b'Zw'):
            syscalls.append({'name': exp.name.decode('utf-8'), 'address': exp.address})

    # Sort the functions by their address
    syscalls.sort(key=lambda x: x['address'])

    # Create the map with the index as the syscall number
    syscall_map = {i: syscall['name'] for i, syscall in enumerate(syscalls)}

    return syscall_map

if __name__ == "__main__":
    dll_path = sys.argv[1]
    syscall_map = get_syscall_map(dll_path)
    outmap = {}
    for ssn, name in syscall_map.items():
        print(f"SSN: {ssn:04d}, Function: {name}")
        outmap[ssn] = name
    with open('/tmp/xp-calls.json', 'w') as fh:
        fh.write(json.dumps(outmap))

