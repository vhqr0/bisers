import argparse
import os
import signal
import socket
import sqlite3
import struct
import sys

from dhcp6lib import *

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--interface')
parser.add_argument('-v', '--verbose', action='store_true', default=False)
parser.add_argument('-f', '--dbfile', default=os.getcwd() + '/dhcp6.db')
args = parser.parse_args()

interface = args.interface
verbose = args.verbose
dbfile = args.dbfile

dhcp6fd = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, 0)
ifindex = 0
if interface:
    ifindex = socket.if_nametoindex(interface)
    dhcp6fd.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                       interface.encode())
dhcp6fd.setsockopt(
    socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP,
    socket.inet_pton(socket.AF_INET6, 'ff02::1:2') +
    struct.pack('@i', ifindex))
dhcp6fd.bind(('', 547))

conn = sqlite3.connect(dbfile)
cur = conn.cursor()
try:
    cur.execute('''
        create table host (
        duid text not null primary key,
        lla text not null,
        gua text not null,
        vendorclass text not null
        )
        ''')
    if verbose:
        print('create table cussess')
except:
    pass

signal.signal(signal.SIGINT, lambda _no, _f: sys.exit(0))

while True:
    buf, lla = dhcp6fd.recvfrom(4096)
    msgtype, _, opts = dhcp6parse(buf)
    if msgtype != DHCP6RENEW or \
       DHCP6CLIENTID not in opts or \
       DHCP6IANA not in opts:
        continue
    duid = opts[DHCP6CLIENTID][0]
    _, _, _, ianaopts = dhcp6parse_iana(opts[DHCP6IANA][0])
    if DHCP6IAADDR not in ianaopts:
        continue
    gua, _, _, _ = dhcp6parse_iaaddr(ianaopts[DHCP6IAADDR][0])
    duid = duid.hex()
    lla = lla[0]
    gua = socket.inet_ntop(socket.AF_INET6, gua)
    vendorclass = ''
    if DHCP6VENDORCLASS in opts:
        num, desc = dhcp6parse_vendorclass(opts[DHCP6VENDORCLASS][0])
        vendorclass = f'{num}: {desc}'
    cur.execute(f'replace into host values (?,?,?,?)', (duid, lla, gua, vendorclass))
    conn.commit()
    if verbose:
        print(f'duid: {duid}')
        print(f'lla: {lla}')
        print(f'gua: {gua}')
        print(f'vendorclass: {vendorclass}')
