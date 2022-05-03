import random
import select
import socket
import struct
import time

from dhcp6lib import *
import pyping

timeout = 0.1
interface = None

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
    pingfd.sendto(buf, (addr, 0))
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
        return True
    return False


dhcp6fd = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, 0)
dhcp6fd.setblocking(False)
if interface:
    dhcp6fd.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                       interface.encode())
dhcp6fd.bind(('', 546))


def dhcp6solicit(servduidfilter=None):
    duid = random_duid_ll()
    trid = random.getrandbits(24)
    iaid = random.getrandbits(32)
    opts = {}
    opts[DHCP6CLIENTID] = [duid]
    opts[DHCP6ELAPSEDTIME] = [dhcp6build_elapsedtime()]
    opts[DHCP6IANA] = [dhcp6build_iana(iaid, 0, 0, {})]
    buf = dhcp6build(DHCP6SOL, trid, opts)
    dhcp6fd.sendto(buf, ('ff02::1', 547))
    tend = time.time() + timeout
    tsel = timeout
    while True:
        rfds = select.select([dhcp6fd], [], [], tsel)[0]
        if len(rfds) == 0:
            break
        buf, _ = dhcp6fd.recvfrom(4096)
        msgtype, rtrid, opts = dhcp6parse(buf)
        if msgtype != DHCP6ADVERT or rtrid != trid or \
           DHCP6SERVERID not in opts or \
           DHCP6IANA not in opts:
            tsel = tend - time.time()
            continue
        servduid = opts[DHCP6SERVERID][0]
        riaid, _, _, ianaopts = dhcp6parse_iana(opts[DHCP6IANA][0])
        if riaid != iaid or DHCP6IAADDR not in ianaopts or \
           servduidfilter is not None and servduidfilter != servduid:
            break
        addr, _, _, _ = dhcp6parse_iaaddr(ianaopts[DHCP6IAADDR][0])
        return addr
    return None


def dhcp6rebind(addr, servduidfilter=None):
    duid = random_duid_ll()
    trid = random.getrandbits(24)
    iaid = random.getrandbits(32)
    opts = {}
    opts[DHCP6CLIENTID] = [duid]
    opts[DHCP6ELAPSEDTIME] = [dhcp6build_elapsedtime()]
    ianaopts = {}
    addrbytes = socket.inet_pton(socket.AF_INET6, addr)
    ianaopts[DHCP6IAADDR] = [dhcp6build_iaaddr(addrbytes, 0, 0, {})]
    opts[DHCP6IANA] = [dhcp6build_iana(iaid, 0, 0, ianaopts)]
    buf = dhcp6build(DHCP6REBIND, trid, opts)
    dhcp6fd.sendto(buf, ('ff02::1', 547))
    tend = time.time() + timeout
    tsel = timeout
    while True:
        rfds = select.select([dhcp6fd], [], [], tsel)[0]
        if len(rfds) == 0:
            break
        buf, servep = dhcp6fd.recvfrom(4096)
        msgtype, rtrid, opts = dhcp6parse(buf)
        if msgtype != DHCP6REPLY or rtrid != trid or \
           DHCP6SERVERID not in opts or \
           DHCP6IANA not in opts:
            tsel = tend - time.time()
            continue
        servduid = opts[DHCP6SERVERID][0]
        riaid, T1, T2, ianaopts = \
            dhcp6parse_iana(opts[DHCP6IANA][0])
        if riaid != iaid or DHCP6IAADDR not in ianaopts or \
           servduidfilter is not None and servduidfilter != servduid:
            tsel = tend - time.time()
            continue
        for iaaddr in ianaopts[DHCP6IAADDR]:
            addr, preftime, validtime, _ = \
                dhcp6parse_iaaddr(iaaddr)
            if addr == addrbytes:
                return validtime > 0
        break
    return None


def dhcp6info():
    duid = random.duid_ll()
    trid = random.getrandbits(24)
    iaid = random.getrandbits(32)
    opts = {}
    opts[DHCP6CLIENTID] = [duid]
    opts[DHCP6ELAPSEDTIME] = [dhcp6build_elapsedtime()]
    opts[DHCP6IANA] = [dhcp6build_iana(iaid, 0, 0, {})]
    reqs = [DHCP6DNS, DHCP6DOMAIN, DHCP6SNTP, DHCP6FQDN]
    opts[DHCP6OPTREQ] = [dhcp6build_optreq(reqs)]
    buf = dhcp6build(DHCP6SOL, trid, opts)
    dhcp6fd.sendto(buf, ('ff02::1', 547))
    tend = time.time() + timeout
    tsel = timeout
    while True:
        rfds = select.select([dhcp6fd], [], [], tsel)[0]
        if len(rfds) == 0:
            break
        buf, servep = dhcp6fd.recvfrom(4096)
        msgtype, rtrid, opts = dhcp6parse(buf)
        if msgtype != DHCP6ADVERT or rtrid != trid or \
           DHCP6SERVERID not in opts or \
           DHCP6IANA not in opts:
            tsel = tend - time.time()
            continue
        servduid = opts[DHCP6SERVERID][0]
        riaid, T1, T2, ianaopts = dhcp6parse_iana(opts[DHCP6IANA][0])
        if riaid != iaid or DHCP6IAADDR not in ianaopts:
            tsel = tend - time.time()
            continue
        addr, preftime, validtime, _ = dhcp6parse_iaaddr(ianaopts[DHCP6IAADDR][0])
        res = {}
        res['address'] = servep[0]
        res['duid'] = servduid
        res['T1'] = T1
        res['T2'] = t2
        res['preftime'] = preftime
        res['validtime'] = validtime
        return res
    return None
