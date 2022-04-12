#!/usr/bin/env python3

import argparse
import ipaddress

parser = argparse.ArgumentParser()
parser.add_argument('addrs_file', type=str)
parser.add_argument('lower_limit', type=str)
parser.add_argument('upper_limit', type=str)
args = parser.parse_args()

addrs_file = args.addrs_file
lower_limit = int(args.lower_limit, 16)
upper_limit = int(args.upper_limit, 16)

total, hit = 0, 0

with open(addrs_file) as f:
    for line in f:
        if line == '\n':
            continue
        addr = int(ipaddress.IPv6Address(line[:-1])) & 0xffffffffffffffff
        total += 1
        if lower_limit <= addr <= upper_limit:
            hit += 1

print(f'{hit}/{total}: {hit/total}')
