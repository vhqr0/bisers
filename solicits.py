#!/usr/bin/env python3

import scapy.all as sp
import scapy.layers.dhcp6 as dhcp6

import argparse
import random
import threading
import time

parser = argparse.ArgumentParser()
parser.add_argument('count', type=int)
args = parser.parse_args()

count = args.count


def send_solicits():
    for _ in range(count):
        time.sleep(0.1)
        p = sp.IPv6(dst='ff02::1:2') / \
            sp.UDP(sport=546, dport=547) / \
            dhcp6.DHCP6_Solicit(trid=random.getrandbits(24)) / \
            dhcp6.DHCP6OptClientId(duid=dhcp6.DUID_LL()) / \
            dhcp6.DHCP6OptElapsedTime() / \
            dhcp6.DHCP6OptIA_NA(iaid=random.getrandbits(32), T1=200, T2=250)
        sp.send(p, verbose=0)


def prn(pkt):
    if dhcp6.DHCP6OptIAAddress in pkt:
        print(pkt[dhcp6.DHCP6OptIAAddress].addr)

t = threading.Thread(target=send_solicits)
t.start()

sp.sniff(filter='ip6 and udp src port 547 and udp dst port 546',
         prn=prn,
         timeout=(0.1 * count + 1),
         quiet=True)

t.join()
