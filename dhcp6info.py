import argparse
import datetime
import ipaddress
import random
import select
import socket
import struct
import sys
import time

from dhcp6lib import *
import pyping

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--interface')
parser.add_argument('-v', '--verbose', action='store_true', default=False)
parser.add_argument('-T', '--timeout', type=float, default=0.1)
parser.add_argument('-I', '--internal', type=float, default=0.0)
parser.add_argument('-n', '--nodelimit', action='store_true', default=False)
parser.add_argument('-d', action='store_const', dest='force', const='ddelimit')
parser.add_argument('-r', action='store_const', dest='force', const='rdelimit')
parser.add_argument('-s', action='store_const', dest='force', const='sdelimit')
parser.add_argument('-W', '--window', type=int, default=3)
parser.add_argument('-C', '--count', type=int, default=64)
args = parser.parse_args()

interface = args.interface
verbose = args.verbose
timeout = args.timeout
internal = args.internal
nodelimit = args.nodelimit
force = args.force
window = args.window
count = args.count

ICMP6_ECHO_REQUEST = 128
ICMP6_ECHO_REPLY = 129

pingfd = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
pingfd.setblocking(False)
if interface:
    pingfd.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                      interface.encode())
pyping.filter_icmp6(pingfd.fileno(), ICMP6_ECHO_REPLY)


def ping(addr):
    seq = random.getrandbits(16)
    buf = struct.pack('!BBHIQ', ICMP6_ECHO_REQUEST, 0, 0, seq, 0)
    try:
        pingfd.sendto(buf, (addr, 0))
    except OSError:
        if verbose:
            print(f'ping {addr}: failed')
        return False
    tend = time.time() + timeout
    tsel = timeout
    while True:
        rfds = select.select([pingfd], [], [], tsel)[0]
        if len(rfds) == 0:
            break
        buf = pingfd.recv(4096)
        rseq, = struct.unpack_from('!I', buffer=buf, offset=4)
        if len(buf) != 16 or rseq != seq:
            tsel = tend - time.time()
            continue
        if verbose:
            print(f'ping {addr}: success')
        return True
    if verbose:
        print(f'ping {addr}: failed')
    return False


dhcp6fd = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, 0)
dhcp6fd.setblocking(False)
if interface:
    dhcp6fd.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                       interface.encode())
dhcp6fd.bind(('', 546))


def dhcp6solicit(servduidfilter=None):
    duid = random_duid_ll()
    trid = random_trid()
    iaid = random_iaid()
    buf = dhcp6build_ext({
        'msgtype': DHCP6SOL,
        'trid': trid,
        'opts': {
            DHCP6CLIENTID: [duid],
            DHCP6ELAPSEDTIME: [0],
            DHCP6IANA: [{
                'iaid': iaid,
                'T1': 0,
                'T2': 0,
                'opts': {}
            }]
        }
    })
    if internal > 0:
        time.sleep(internal)
    dhcp6fd.sendto(buf, ('ff02::1', 547))
    tend = time.time() + timeout
    tsel = timeout
    while True:
        rfds = select.select([dhcp6fd], [], [], tsel)[0]
        if len(rfds) == 0:
            break
        buf, _ = dhcp6fd.recvfrom(4096)
        res = dhcp6parse_ext(buf)
        opts = res['opts']
        if res['msgtype'] != DHCP6ADVERT or \
           res['trid'] != trid or \
           DHCP6SERVERID not in opts or \
           DHCP6IANA not in opts:
            tsel = tend - time.time()
            continue
        servduid = opts[DHCP6SERVERID][0]
        iana = opts[DHCP6IANA][0]
        if iana['iaid'] != iaid or \
           DHCP6IAADDR not in iana['opts'] or \
           servduidfilter is not None and servduidfilter != servduid:
            break
        addr = iana['opts'][DHCP6IAADDR][0]['addr']
        addr = socket.inet_ntop(socket.AF_INET6, addr)
        if verbose:
            print(f'solicit: {addr}')
        return addr
    if verbose:
        print('solicit: failed')
    return None


def dhcp6rebind(addr, servduidfilter=None):
    duid = random_duid_ll()
    trid = random_trid()
    iaid = random_iaid()
    addrbytes = socket.inet_pton(socket.AF_INET6, addr)
    buf = dhcp6build_ext({
        'msgtype': DHCP6REBIND,
        'trid': trid,
        'opts': {
            DHCP6CLIENTID: [duid],
            DHCP6ELAPSEDTIME: [0],
            DHCP6IANA: [{
                'iaid': iaid,
                'T1': 0,
                'T2': 0,
                'opts': {
                    DHCP6IAADDR: [{
                        'addr': addrbytes,
                        'preftime': 0,
                        'validtime': 0,
                        'opts': {}
                    }]
                }
            }],
        }
    })
    if internal > 0:
        time.sleep(internal)
    dhcp6fd.sendto(buf, ('ff02::1', 547))
    tend = time.time() + timeout
    tsel = timeout
    while True:
        rfds = select.select([dhcp6fd], [], [], tsel)[0]
        if len(rfds) == 0:
            break
        buf, servep = dhcp6fd.recvfrom(4096)
        res = dhcp6parse_ext(buf)
        opts = res['opts']
        if res['msgtype'] != DHCP6REPLY or \
           res['trid'] != trid or \
           DHCP6SERVERID not in opts or \
           DHCP6IANA not in opts:
            tsel = tend - time.time()
            continue
        servduid = opts[DHCP6SERVERID][0]
        iana = opts[DHCP6IANA][0]
        if iana['iaid'] != iaid or \
           DHCP6IAADDR not in iana['opts'] or \
           servduidfilter is not None and servduidfilter != servduid:
            tsel = tend - time.time()
            continue
        for i in iana['opts'][DHCP6IAADDR]:
            if i['addr'] == addrbytes:
                validtime = i['validtime']
                if verbose:
                    print(f'rebind {addr}:'
                          f'{"success" if validtime > 0 else "failed"}')
                return validtime > 0
        break
    return None


def dhcp6info_1():
    duid = random_duid_ll()
    trid = random_trid()
    iaid = random_iaid()
    buf = dhcp6build_ext({
        'msgtype': DHCP6SOL,
        'trid': trid,
        'opts': {
            DHCP6CLIENTID: [duid],
            DHCP6ELAPSEDTIME: [0],
            DHCP6IANA: [{
                'iaid': iaid,
                'T1': 0,
                'T2': 0,
                'opts': {}
            }],
            DHCP6OPTREQ: [[DHCP6DNS, DHCP6DOMAIN]]
        }
    })
    dhcp6fd.sendto(buf, ('ff02::1', 547))
    tend = time.time() + timeout
    tsel = timeout
    while True:
        rfds = select.select([dhcp6fd], [], [], tsel)[0]
        if len(rfds) == 0:
            break
        buf, servep = dhcp6fd.recvfrom(4096)
        res = dhcp6parse_ext(buf)
        opts = res['opts']
        if res['msgtype'] != DHCP6ADVERT or \
           res['trid'] != trid or \
           DHCP6SERVERID not in opts or \
           DHCP6IANA not in opts:
            tsel = tend - time.time()
            continue
        servduid = opts[DHCP6SERVERID][0]
        iana = opts[DHCP6IANA][0]
        if iana['iaid'] != iaid or \
           DHCP6IAADDR not in iana['opts']:
            tsel = tend - time.time()
            continue
        iaaddr = iana['opts'][DHCP6IAADDR][0]
        res['duid'] = servduid
        duidtype, = struct.unpack_from('!H', buffer=servduid, offset=0)
        if duidtype == 1:
            secs, = struct.unpack_from('!I', buffer=servduid, offset=4)
            date = datetime.datetime(2000, 1, 1)
            date += datetime.timedelta(seconds=secs)
            res['duidtype'] = 'llt'
            res['duidlladdr'] = servduid[8:].hex()
            res['duiddate'] = date
        elif duidtype == 3:
            res['duidtype'] = 'll'
            res['duidlladdr'] = servduid[4:].hex()
        else:
            res['duidtype'] = 'unknown'
        res['address'] = servep[0]
        res['T1'] = iana['T1']
        res['T2'] = iana['T2']
        res['preftime'] = iaaddr['preftime']
        res['validtime'] = iaaddr['validtime']
        if DHCP6DNS in opts:
            res['dns'] = opts[DHCP6DNS][0]
        if DHCP6DOMAIN in opts:
            res['domain'] = opts[DHCP6DOMAIN][0]
        res['solicited_address'] = socket.inet_ntop(socket.AF_INET6,
                                                    iaaddr['addr'])
        return res
    return None


def dllimit(l, u):
    h = (l + u) // 2
    if l >= u:
        return h
    _h = str(ipaddress.IPv6Address(h))
    if ping(_h):
        return dllimit(l, h - 1)
    for i in range(max(h - window, l), min(h + window + 1, u + 1)):
        if i == h:
            continue
        _i = str(ipaddress.IPv6Address(i))
        if ping(_i):
            return dllimit(l, i - 1)
    return dllimit(h + 1, u)


def dulimit(l, u):
    h = (l + u) // 2
    if l >= u:
        return h
    _h = str(ipaddress.IPv6Address(h))
    if ping(_h):
        return dulimit(h + 1, u)
    for i in range(max(h - window, l), min(h + window + 1, u + 1)):
        if i == h:
            continue
        _i = str(ipaddress.IPv6Address(i))
        if ping(_i):
            return dulimit(i + 1, u)
    return dulimit(l, h - 1)


def ddelimit(addr):
    _addr = int(ipaddress.IPv6Address(addr))
    _l = _addr & 0xffffffffffffffff0000000000000000
    _u = _l + 0xffffffffffffffff
    return dllimit(_l, _addr), dulimit(_addr, _u)


def rllimit(l, u, servduid):
    h = (l + u) // 2
    if l >= u:
        return h
    _h = str(ipaddress.IPv6Address(h))
    if dhcp6rebind(_h, servduid) or ping(_h):
        return rllimit(l, h - 1, servduid)
    else:
        return rllimit(h + 1, u, servduid)


def rulimit(l, u, servduid):
    h = (l + u) // 2
    if l >= u:
        return h
    _h = str(ipaddress.IPv6Address(h))
    if dhcp6rebind(_h, servduid) or ping(_h):
        return rulimit(h + 1, u, servduid)
    else:
        return rulimit(l, h - 1, servduid)


def rdelimit(addr, servduid):
    _addr = int(ipaddress.IPv6Address(addr))
    _l = _addr & 0xffffffffffffffff0000000000000000
    _u = _l + 0xffffffffffffffff
    return rllimit(_l, _addr, servduid), rulimit(_addr, _u, servduid)


def sdelimit(addr, servduid):
    _addr = int(ipaddress.IPv6Address(addr))
    l, u = _addr, _addr
    for _ in range(count):
        addr = dhcp6solicit(servduid)
        _addr = int(ipaddress.IPv6Address(addr))
        l, u = min(l, _addr), max(u, _addr)
    d = (l - u) // count
    return l - d, u + d


def dhcp6info(delimit=True):
    res = dhcp6info_1()
    if res is None:
        return None
    res['aat'] = 'unknown'
    addr0 = res['solicited_address']
    addr1 = dhcp6solicit(servduidfilter=res['duid'])
    if addr1 is None:
        return res
    _addr0 = int(ipaddress.IPv6Address(addr0))
    _addr1 = int(ipaddress.IPv6Address(addr1))
    if _addr0 == _addr1 + 1 or _addr0 == _addr1:
        res['aat'] = 'linear'
    else:
        res['aat'] = 'random'
        addr2 = str(ipaddress.IPv6Address(_addr0 - 1))
        addr3 = str(ipaddress.IPv6Address(_addr0 + 1))
        res2 = dhcp6rebind(addr2, servduidfilter=res['duid'])
        res3 = dhcp6rebind(addr3, servduidfilter=res['duid'])
        if res2 is True or res3 is True:
            res['aat'] = 'random+rebind'
    if delimit:
        limit = None
        if force is None:
            if res['aat'] == 'linear':
                limit = ddelimit(res['solicited_address'])
            elif res['aat'] == 'random+rebind':
                limit = rdelimit(res['solicited_address'], res['duid'])
            elif res['aat'] == 'random':
                limit = sdelimit(res['solicited_address'], res['duid'])
        elif force == 'ddelimit':
            limit = ddelimit(res['solicited_address'])
        elif force == 'rdelimit':
            limit = rdelimit(res['solicited_address'], res['duid'])
        elif force == 'sdelimit':
            limit = sdelimit(res['solicited_address'], res['duid'])
        if limit is not None:
            res['limit'] = (str(ipaddress.IPv6Address(limit[0])),
                            str(ipaddress.IPv6Address(limit[1])))
    return res


res = dhcp6info(not nodelimit)

if res is None:
    print('no dhcp6 server found')
    sys.exit(1)

print(f'address: {res["address"]}')
print(f'duid: {res["duid"].hex()}')
print(f'duidtype: {res["duidtype"]}')
if 'duiddate' in res:
    print(f'duiddate: {res["duiddate"]}')
if 'duidlladdr' in res:
    print(f'duidlladdr: {res["duidlladdr"]}')
print(f'T1: {res["T1"]}')
print(f'T2: {res["T2"]}')
print(f'validtime: {res["validtime"]}')
print(f'preftime: {res["preftime"]}')
if 'dns' in res:
    for dns in res['dns']:
        print(f'dns: {dns}')
if 'domain' in res:
    for domain in res['domain']:
        print(f'domain: {domain}')
if 'aat' in res:
    print(f'aat: {res["aat"]}')
if 'limit' in res:
    print(f'limit: {res["limit"][0]} ~ {res["limit"][1]}')
