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
from icmp6filter import *

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--interface')
parser.add_argument('-v', '--verbose', action='store_true', default=False)
parser.add_argument('-T', '--timeout', type=float, default=0.1)
parser.add_argument('-I', '--internal', type=float, default=0.0)
parser.add_argument('-R', '--relay')
parser.add_argument('-L', '--linkaddr')
parser.add_argument('-P', '--peeraddr', default='fe80::1')
parser.add_argument('-H', '--hopcount', type=int, default=0)
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
relaydest = args.relay
relaylinkaddr = args.linkaddr or relaydest
if relaylinkaddr:
    relaylinkaddr = socket.inet_pton(socket.AF_INET6, relaylinkaddr)
relaypeeraddr = socket.inet_pton(socket.AF_INET6, args.peeraddr)
relayhopcount = args.hopcount
nodelimit = args.nodelimit
force = args.force
window = args.window
count = args.count

pingfd = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
pingfd.setblocking(False)
if interface:
    pingfd.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                      interface.encode())
icmp6f = ICMP6Filter()
icmp6f.setblockall()
icmp6f.setpass(ICMP6_ECHOREP)
icmp6f.setsockopt(pingfd)


def ping(addr):
    addr = socket.inet_ntop(socket.AF_INET6, addr)
    seq = random.getrandbits(16)
    buf = struct.pack('!BBHIQ', ICMP6_ECHOREQ, 0, 0, seq, 0)
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


lep, rep = ('', 546), ('ff02::1:2', 547)
if relaydest:
    lep, rep = ('', 547), (relaydest, 547)

dhcp6fd = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, 0)
dhcp6fd.setblocking(False)
if interface:
    dhcp6fd.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                       interface.encode())
dhcp6fd.bind(lep)

servduidfilter = None


def dhcp6solicit(rapidcommit=False):
    duid = random_duid_ll()
    trid = random_trid()
    iaid = random_iaid()
    res = {
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
    }
    if rapidcommit:
        res['opts'][DHCP6RAPIDCOMMIT] = [b'']
    if relaydest:
        res['relay'] = {
            'msgtype': DHCP6RELAYFORW,
            'hopcount': relayhopcount,
            'linkaddr': relaylinkaddr,
            'peeraddr': relaypeeraddr
        }
    buf = dhcp6build_ext(res)
    if internal > 0:
        time.sleep(internal)
    dhcp6fd.sendto(buf, rep)
    tend = time.time() + timeout
    tsel = timeout
    while True:
        rfds = select.select([dhcp6fd], [], [], tsel)[0]
        if len(rfds) == 0:
            break
        buf, _ = dhcp6fd.recvfrom(4096)
        res = dhcp6parse_ext(buf)
        opts = res['opts']
        msgtype = DHCP6REPLY if rapidcommit else DHCP6ADVERT
        if res['msgtype'] != msgtype or \
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
        if verbose:
            print(f'solicit: {socket.inet_ntop(socket.AF_INET6, addr)}')
        return addr
    if verbose:
        print('solicit: failed')
    return None


def dhcp6rebind(addr):
    duid = random_duid_ll()
    trid = random_trid()
    iaid = random_iaid()
    res = {
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
                        'addr': addr,
                        'preftime': 0,
                        'validtime': 0,
                        'opts': {}
                    }]
                }
            }],
        }
    }
    if relaydest:
        res['relay'] = {
            'msgtype': DHCP6RELAYFORW,
            'hopcount': relayhopcount,
            'linkaddr': relaylinkaddr,
            'peeraddr': relaypeeraddr
        }
    buf = dhcp6build_ext(res)
    if internal > 0:
        time.sleep(internal)
    dhcp6fd.sendto(buf, rep)
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
            if i['addr'] == addr:
                validtime = i['validtime']
                if verbose:
                    print(f'rebind {socket.inet_ntop(socket.AF_INET6, addr)}:'
                          f'{"success" if validtime > 0 else "failed"}')
                return validtime > 0
        break
    return None


def dhcp6leasequery(addr):
    duid = random_duid_ll()
    trid = random_trid()
    iaid = random_iaid()
    res = {
        'msgtype': DHCP6LEASEQUERY,
        'trid': trid,
        'opts': {
            DHCP6CLIENTID: [duid],
            DHCP6SERVERID: [servduidfilter],
            DHCP6LQQUERY: [{
                'querytype': DHCP6QUERYBYADDR,
                'linkaddr': addr,
                'opts': {
                    DHCP6IAADDR: [{
                        'addr': addr,
                        'preftime': 0,
                        'validtime': 0,
                        'opts': {}
                    }]
                }
            }]
        }
    }
    if relaydest:
        res['relay'] = {
            'msgtype': DHCP6RELAYFORW,
            'hopcount': relayhopcount,
            'linkaddr': relaylinkaddr,
            'peeraddr': relaypeeraddr
        }
    buf = dhcp6build_ext(res)
    if internal > 0:
        time.sleep(internal)
    dhcp6fd.sendto(buf, rep)
    tend = time.time() + timeout
    tsel = timeout
    while True:
        rfds = select.select([dhcp6fd], [], [], tsel)[0]
        if len(rfds) == 0:
            break
        buf, servep = dhcp6fd.recvfrom(4096)
        res = dhcp6parse_ext(buf)
        opts = res['opts']
        if res['msgtype'] != DHCP6LEASEQUERYREPL or \
           res['trid'] != trid or \
           DHCP6SERVERID not in opts or \
           DHCP6LQCLIENTDATA not in opts:
            tsel = tend - time.time()
            continue
        servduid = opts[DHCP6CLIENTID][0]
        clientdata = opts[DHCP6LQCLIENTDATA][0]
        if servduidfilter is not None and servduidfilter != servduid:
            tsel = tend - time.time()
            continue
        return DHCP6CLIENTID in clientdata
    return None


def dhcp6info_1():
    global servduidfilter
    duid = random_duid_ll()
    trid = random_trid()
    iaid = random_iaid()
    res = {
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
    }
    if relaydest:
        res['relay'] = {
            'msgtype': DHCP6RELAYFORW,
            'hopcount': relayhopcount,
            'linkaddr': relaylinkaddr,
            'peeraddr': relaypeeraddr
        }
    buf = dhcp6build_ext(res)
    dhcp6fd.sendto(buf, rep)
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
        # address
        res['address'] = servep[0]
        # duid
        servduidfilter = servduid
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
        # iana
        res['T1'] = iana['T1']
        res['T2'] = iana['T2']
        res['preftime'] = iaaddr['preftime']
        res['validtime'] = iaaddr['validtime']
        res['iaaddr'] = iaaddr['addr']
        if DHCP6DNS in opts:
            res['dns'] = opts[DHCP6DNS][0]
        if DHCP6DOMAIN in opts:
            res['domain'] = opts[DHCP6DOMAIN][0]
        return res
    return None


def dhcp6info_cap(res):
    _iaaddr = int.from_bytes(res['iaaddr'], byteorder='big')
    addr0 = (_iaaddr - 1).to_bytes(16, byteorder='big')
    addr1 = (_iaaddr + 1).to_bytes(16, byteorder='big')
    res['rebind'] = dhcp6rebind(addr0) or dhcp6rebind(addr1)
    res['rc'] = dhcp6solicit(True) is not None
    res['lq'] = dhcp6leasequery(res['iaaddr']) is not None
    addr0 = dhcp6solicit()
    addr1 = dhcp6solicit()
    if addr0 is None or addr1 is None:
        res['aat'] = 'unknown'
    else:
        _addr0 = int.from_bytes(addr0, byteorder='big')
        _addr1 = int.from_bytes(addr1, byteorder='big')
        if _addr0 == _addr1 + 1 or _addr0 == _addr1 - 1:
            res['aat'] = 'linear'
        else:
            res['aat'] = 'random'
    return res


def dllimit(l, u):
    h = (l + u) // 2
    if l >= u:
        return h
    _h = h.to_bytes(16, byteorder='big')
    if ping(_h):
        return dllimit(l, h - 1)
    for i in range(max(h - window, l), min(h + window + 1, u + 1)):
        if i == h:
            continue
        _i = i.to_bytes(16, byteorder='big')
        if ping(_i):
            return dllimit(l, i - 1)
    return dllimit(h + 1, u)


def dulimit(l, u):
    h = (l + u) // 2
    if l >= u:
        return h
    _h = h.to_bytes(16, byteorder='big')
    if ping(_h):
        return dulimit(h + 1, u)
    for i in range(max(h - window, l), min(h + window + 1, u + 1)):
        if i == h:
            continue
        _i = i.to_bytes(16, byteorder='big')
        if ping(_i):
            return dulimit(i + 1, u)
    return dulimit(l, h - 1)


def ddelimit(addr):
    _addr = int.from_bytes(addr, byteorder='big')
    _l = _addr & 0xffffffffffffffff0000000000000000
    _u = _l + 0xffffffffffffffff
    return dllimit(_l, _addr), dulimit(_addr, _u)


def rllimit(l, u):
    h = (l + u) // 2
    if l >= u:
        return h
    _h = h.to_bytes(16, byteorder='big')
    if dhcp6rebind(_h) or ping(_h):
        return rllimit(l, h - 1)
    else:
        return rllimit(h + 1, u)


def rulimit(l, u):
    h = (l + u) // 2
    if l >= u:
        return h
    _h = h.to_bytes(16, byteorder='big')
    if dhcp6rebind(_h) or ping(_h):
        return rulimit(h + 1, u)
    else:
        return rulimit(l, h - 1)


def rdelimit(addr):
    _addr = int.from_bytes(addr, byteorder='big')
    _l = _addr & 0xffffffffffffffff0000000000000000
    _u = _l + 0xffffffffffffffff
    return rllimit(_l, _addr), rulimit(_addr, _u)


def sdelimit(addr):
    _addr = int.from_bytes(addr, byteorder='big')
    l, u = _addr, _addr
    for _ in range(count):
        addr = dhcp6solicit()
        _addr = int.from_bytes(addr, byteorder='big')
        l, u = min(l, _addr), max(u, _addr)
    d = (l - u) // count
    return l - d, u + d


def dhcp6info(delimit=True):
    res = dhcp6info_1()
    if res is None:
        return None
    res = dhcp6info_cap(res)
    if delimit:
        limit = None
        iaaddr = res['iaaddr']
        if force is None:
            if res['aat'] == 'linear':
                limit = ddelimit(iaaddr)
            elif res['aat'] == 'random':
                if res['rebind']:
                    limit = rdelimit(iaaddr)
                else:
                    limit = sdelimit(iaaddr)
        elif force == 'ddelimit':
            limit = ddelimit(iaaddr)
        elif force == 'rdelimit':
            limit = rdelimit(iaaddr)
        elif force == 'sdelimit':
            limit = sdelimit(iaaddr)
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
print(f' \_type: {res["duidtype"]}')
if 'duidlladdr' in res:
    print(f' \_lladdr: {res["duidlladdr"]}')
if 'duiddate' in res:
    print(f' \_date: {res["duiddate"]}')
print('iana:')
print(f' \_T1: {res["T1"]}')
print(f' \_T2: {res["T2"]}')
print(f' \_validtime: {res["validtime"]}')
print(f' \_preftime: {res["preftime"]}')
print(f' \_addr: {socket.inet_ntop(socket.AF_INET6, res["iaaddr"])}')
if 'dns' in res:
    print('dns:')
    for dns in res['dns']:
        print(f' \_{dns}')
if 'domain' in res:
    print('domain:')
    for domain in res['domain']:
        print(f' \_{domain}')
print('capability:')
if 'rc' in res:
    print(f' \_rapidcommit: {res["rc"]}')
if 'lq' in res:
    print(f' \_leasequery: {res["lq"]}')
if 'aat' in res:
    print(f' \_aat: {res["aat"]}')
if 'rebind' in res:
    print(f' \_rebind: {res["rebind"]}')
if 'limit' in res:
    print(f' \_limit: {res["limit"][0]} ~ {res["limit"][1]}')
