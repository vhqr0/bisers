#!/usr/bin/env python3

import argparse

parser = argparse.ArgumentParser()
parser.add_argument('in_file', type=str)
args = parser.parse_args()

in_file = args.in_file
addrs = []
lower_limit, upper_limit = 0, 0
prob1s, prob2s, count = 0, 0, 0

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
                    addrs.append(int(a[:-1], 16))
            lower_limit = int(s[2], 16)
            upper_limit = int(s[3], 16)
            prob1s, prob2s, count = 0, 0, 0
            continue
        if s[0] == '%':
            print(line[:-1], end='')
            if count == 0:
                print(' 0 0')
            else:
                print(f' {prob1s/count:.3} {prob2s/count:.3}')
            prob1s, prob2s, count = 0, 0, 0
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
        prob1 = hit / len(addrs)
        prob2 = (abs(l - lower_limit) + abs(u - upper_limit)) / \
            (upper_limit - lower_limit)
        prob2 = 1 - prob2
        prob1s += prob1
        prob2s += prob2
        count += 1
        print(f'{prob1:.3}\t{prob2:.3}')
