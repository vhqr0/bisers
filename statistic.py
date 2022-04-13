#!/usr/bin/env python3

import argparse
import ipaddress

parser = argparse.ArgumentParser()
parser.add_argument('in_file', type=str)
args = parser.parse_args()

in_file = args.in_file
addrs = []
lower_limit, upper_limit = 0, 0

with open(in_file) as f:
    for line in f:
        if line == '\n':
            print('')
            continue
        s = line.split()
        if s[0] == '#':
            print(line[:-1])
            addrs = []
            with open(s[1]) as fa:
                for a in fa:
                    if a == '\n':
                        continue
                    addrs.append(
                        int(ipaddress.IPv6Address(a[:-1]))
                        & 0xffffffffffffffff)
            lower_limit = int(s[2], 16)
            upper_limit = int(s[3], 16)
            continue
        print(line[:-1], end='\t')
        l = int(s[1], 16)
        u = int(s[2], 16)
        if l == u:
            print('0\t0')
            continue
        hit = 0
        for addr in addrs:
            if l <= addr <= u:
                hit += 1
        print(f'{hit/len(addrs)}\t{(abs(l-lower_limit)+abs(u-upper_limit))/(upper_limit-lower_limit)}')
