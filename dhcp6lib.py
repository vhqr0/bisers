import struct
import random
import socket

DHCP6SOL = 1
DHCP6ADVERT = 2
DHCP6REQ = 3
DHCP6CONFIRM = 4
DHCP6RENEW = 5
DHCP6REBIND = 6
DHCP6REPLY = 7
DHCP6RELEASE = 8
DHCP6DECLINE = 9
DHCP6RECONF = 10
DHCP6INFOREQ = 11
DHCP6RELAYFORW = 12
DHCP6RELAYREPL = 13

DHCP6CLIENTID = 1
DHCP6SERVERID = 2
DHCP6IANA = 3
DHCP6IATA = 4
DHCP6IAADDR = 5
DHCP6OPTREQ = 6
DHCP6PREF = 7
DHCP6ELAPSEDTIME = 8
DHCP6RELAYMSG = 9
DHCP6AUTH = 11
DHCP6SERVERUNICAST = 12
DHCP6STATUSCODE = 13
DHCP6RAPIDCOMMIT = 14
DHCP6USERCLASS = 15
DHCP6VENDORCLASS = 16
DHCP6VENDORSPEC = 17
DHCP6INTERFACEID = 18
DHCP6RECONFMSG = 19
DHCP6RECONFACCEPT = 20
DHCP6DNS = 23
DHCP6DOMAIN = 24
DHCP6IAPD = 25
DHCP6IAPREFIX = 26
DHCP6SNTP = 31
DHCP6FQDN = 39

DHCP6SUCCESS = 0
DHCP6UNSPECFAIL = 1
DHCP6NOADDRSAVAIL = 2
DHCP6NOBINDING = 3
DHCP6NOTONLINK = 4
DHCP6USEMULTICAST = 5


def dhcp6parseopts(buf, offset):
    opts = {}
    cur = offset
    while cur < len(buf):
        opttype, optlen = struct.unpack_from('!HH', buffer=buf, offset=cur)
        cur += 4
        optdata = buf[cur:cur + optlen]
        cur += optlen
        if opttype not in opts:
            opts[opttype] = []
        opts[opttype].append(optdata)
    return opts


def dhcp6buildopts(opts):
    buf = b''
    for opt in opts:
        datas = opts[opt]
        for data in datas:
            buf += struct.pack('!HH', opt, len(data))
            buf += data
    return buf


def dhcp6parse(buf):
    msg, = struct.unpack_from('!I', buffer=buf, offset=0)
    msgtype = (msg & 0xff000000) >> 24
    trid = msg & 0xffffff
    opts = dhcp6parseopts(buf, 4)
    return msgtype, trid, opts


def dhcp6build(msgtype, trid, opts):
    msg = (msgtype << 24) + trid
    buf = struct.pack('!I', msg)
    buf += dhcp6buildopts(opts)
    return buf


def dhcp6parse_iana(buf):
    iaid, T1, T2 = struct.unpack_from('!III', buffer=buf, offset=0)
    subopts = dhcp6parseopts(buf, 12)
    return iaid, T1, T2, subopts


def dhcp6build_iana(iaid, T1, T2, subopts):
    buf = struct.pack('!III', iaid, T1, T2)
    buf += dhcp6buildopts(subopts)
    return buf


def dhcp6parse_iaaddr(buf):
    addr, preftime, validtime = struct.unpack('!16sii', buf)
    subopts = dhcp6parseopts(buf, 24)
    return addr, preftime, validtime, subopts


def dhcp6build_iaaddr(addr, preftime, validtime, subopts):
    buf = struct.pack('!16sii', addr, preftime, validtime)
    buf += dhcp6buildopts(subopts)
    return buf


def dhcp6build_optreq(reqs):
    buf = b''
    for req in reqs:
        buf += struct.pack('!H', req)
    return buf


def dhcp6parse_dns(buf):
    res = []
    cur = 0
    while cur < len(buf):
        res.append(socket.inet_ntop(socket.AF_INET6, buf[cur:cur+16]))
        cur += 16
    return res


def dhcp6parse_domain(buf):
    res = []
    cur = 0
    while cur < len(buf):
        domain = ''
        clen = buf[cur]
        cur += 1
        while clen != 0:
            domain += buf[cur:cur+clen].decode()
            domain += '.'
            cur += clen
            clen = buf[cur]
            cur += 1
        res.append(domain)
    return res


def dhcp6build_elapsedtime(time=0):
    return struct.pack('!H', time)


def duid_ll(mac):
    return struct.pack('!HH6s', 3, 1, mac)


def random_duid_ll():
    return duid_ll(random.randbytes(6))
