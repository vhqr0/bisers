import struct
import random
import socket
import time

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


def duid_ll(mac):
    return struct.pack('!HH6s', 3, 1, mac)


def duid_llt(timestamp, mac):
    return struct.pack('!HHI6s', 1, 1, timestamp, mac)


def random_duid_ll():
    return duid_ll(random.randbytes(6))


def random_duid_llt():
    return duid_llt(round(time.time()), random.randbytes(6))


def random_trid():
    return random.getrandbits(24)


def random_iaid():
    return random.getrandbits(32)


# parse


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


def dhcp6parse(buf):
    msg, = struct.unpack_from('!I', buffer=buf, offset=0)
    msgtype = (msg & 0xff000000) >> 24
    trid = msg & 0xffffff
    opts = dhcp6parseopts(buf, 4)
    return msgtype, trid, opts


def dhcp6parse_relay(buf):
    msgtype, hopcount, linkaddr, peeraddr = struct.unpack_from('!BB16s16s')
    opts = dhcp6parseopts(buf, 34)
    return msgtype, hopcount, linkaddr, peeraddr, opts


def dhcp6parse_ia(buf):
    iaid, T1, T2 = struct.unpack_from('!III', buffer=buf, offset=0)
    subopts = dhcp6parseopts(buf, 12)
    return iaid, T1, T2, subopts


def dhcp6parse_iaaddr(buf):
    addr, preftime, validtime = struct.unpack('!16sii', buf)
    subopts = dhcp6parseopts(buf, 24)
    return addr, preftime, validtime, subopts


def dhcp6parse_iaprefix(buf):
    preftime, validtime, prefixlength, prefix = struct.unpack('!iiB16s')
    subopts = dhcp6parseopts(buf, 25)
    return preftime, validtime, prefixlength, prefix, subopts


def dhcp6parse_elapsedtime(buf):
    return struct.unpack('!H', buf)


def dhcp6parse_optreq(buf):
    return list(buf)


def dhcp6parse_dns(buf):
    res = []
    cur = 0
    while cur < len(buf):
        res.append(socket.inet_ntop(socket.AF_INET6, buf[cur:cur + 16]))
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
            domain += buf[cur:cur + clen].decode()
            domain += '.'
            cur += clen
            clen = buf[cur]
            cur += 1
        res.append(domain)
    return res


def dhcp6parse_vendorclass(buf):
    num, = struct.unpack('!I', buf)
    desc = buf[4:].decode()
    return num, desc


def dhcp6parseopts_ext(opts):
    for k, v in opts.items():
        if k in (DHCP6IANA, DHCP6IATA, DHCP6IAPD):
            opts[k] = []
            for i in v:
                iaid, T1, T2, subopts = dhcp6parse_ia(i)
                opts[k].append({
                    'iaid': iaid,
                    'T1': T1,
                    'T2': T2,
                    'opts': dhcp6parseopts_ext(subopts)
                })
        elif k == DHCP6IAADDR:
            opts[k] = []
            for i in v:
                addr, preftime, validtime, subopts = dhcp6parse_iaaddr(i)
                opts[k].append({
                    'addr': addr,
                    'preftime': preftime,
                    'validtime': validtime,
                    'opts': dhcp6parseopts_ext(subopts)
                })
        elif k == DHCP6IAPREFIX:
            opts[k] = []
            for i in v:
                preftime, validtime, prefixlength, prefix, subopts = \
                    dhcp6parse_iaprefix(i)
                opts[k].append({
                    'preftime': preftime,
                    'validtime': validtime,
                    'prefixlength': prefixlength,
                    'prefix': prefix,
                    'opts': dhcp6parseopts_ext(subopts)
                })
        elif k == DHCP6ELAPSEDTIME:
            opts[k] = []
            for i in v:
                opts[k].append(dhcp6parse_elapsedtime(i))
        elif k == DHCP6OPTREQ:
            opts[k] = []
            for i in v:
                opts[k].append(dhcp6parse_optreq(i))
        elif k == DHCP6DNS:
            opts[k] = []
            for i in v:
                opts[k].append(dhcp6parse_dns(i))
        elif k == DHCP6DOMAIN:
            opts[k] = []
            for i in v:
                opts[k].append(dhcp6parse_domain(i))
        elif k == DHCP6VENDORCLASS:
            opts[k] = []
            for i in v:
                num, desc = dhcp6parse_vendorclass(i)
                opts[k].append({'num': num, 'desc': desc})
    return opts


def dhcp6parse_ext(buf):
    res = {}
    if buf[0] in (DHCP6RELAYFORW, DHCP6RELAYREPL):
        msgtype, hopcount, linkaddr, peeraddr, opts = dhcp6parse_relay()
        res['relay'] = {
            'msgtype': msgtype,
            'hopcount': hopcount,
            'linkaddr': linkaddr,
            'peeraddr': peeraddr
        }
        buf = opts[DHCP6RELAYMSG]
    msgtype, trid, opts = dhcp6parse(buf)
    res['msgtype'] = msgtype
    res['trid'] = trid
    res['opts'] = dhcp6parseopts_ext(opts)
    return res


# build


def dhcp6buildopts(opts):
    buf = b''
    for opt in opts:
        datas = opts[opt]
        for data in datas:
            buf += struct.pack('!HH', opt, len(data))
            buf += data
    return buf


def dhcp6build(msgtype, trid, opts):
    msg = (msgtype << 24) + trid
    buf = struct.pack('!I', msg)
    buf += dhcp6buildopts(opts)
    return buf


def dhcp6build_relay(msgtype, hopcount, linkaddr, peeraddr, opts):
    buf = struct.pack('!BB16s16s', msgtype, hopcount, linkaddr, peeraddr)
    buf += dhcp6buildopts(opts)
    return buf


def dhcp6build_ia(iaid, T1, T2, subopts):
    buf = struct.pack('!III', iaid, T1, T2)
    buf += dhcp6buildopts(subopts)
    return buf


def dhcp6build_iaaddr(addr, preftime, validtime, subopts):
    buf = struct.pack('!16sii', addr, preftime, validtime)
    buf += dhcp6buildopts(subopts)
    return buf


def dhcp6build_iaprefix(preftime, validtime, prefixlength, prefix, subopts):
    buf = struct.pack('!iiB16s', preftime, validtime, prefixlength, prefix)
    buf += dhcp6buildopts(subopts)
    return buf


def dhcp6build_elapsedtime(time=0):
    return struct.pack('!H', time)


def dhcp6build_optreq(reqs):
    buf = b''
    for req in reqs:
        buf += struct.pack('!H', req)
    return buf


def dhcp6build_dns(dnss):
    buf = b''
    for dns in dnss:
        buf += socket.inet_pton(socket.AF_INET6, dns)
    return buf


def dhcp6build_domain(domains):
    buf = b''
    for domain in domains:
        for sp in domain.split('.'):
            b += chr(len(sp)).encode()
            b += sp.encode()
    return buf


def dhcp6build_vendorclass(num, desc):
    buf = struct.pack('!I', num)
    buf += desc
    return buf


def dhcp6buildopts_ext(opts):
    for k, v in opts.items():
        if k in (DHCP6IANA, DHCP6IATA, DHCP6IAPD):
            opts[k] = []
            for i in v:
                opts[k].append(
                    dhcp6build_ia(iaid=i['iaid'],
                                  T1=i['T1'],
                                  T2=i['T2'],
                                  subopts=dhcp6buildopts_ext(i['opts'])))
        elif k == DHCP6IAADDR:
            opts[k] = []
            for i in v:
                opts[k].append(
                    dhcp6build_iaaddr(addr=i['addr'],
                                      preftime=i['preftime'],
                                      validtime=i['validtime'],
                                      subopts=dhcp6buildopts_ext(i['opts'])))
        elif k == DHCP6IAPREFIX:
            opts[k] = []
            for i in v:
                opts[k].append(
                    dhcp6build_iaprefix(preftime=i['preftime'],
                                        validtime=i['validtime'],
                                        prefixlength=i['prefixlength'],
                                        prefix=i['prefix'],
                                        subopts=dhcp6buildopts_ext(i['opts'])))
        elif k == DHCP6ELAPSEDTIME:
            opts[k] = []
            for i in v:
                opts[k].append(dhcp6build_elapsedtime(i))
        elif k == DHCP6OPTREQ:
            opts[k] = []
            for i in v:
                opts[k].append(dhcp6build_optreq(i))
        elif k == DHCP6DNS:
            opts[k] = []
            for i in v:
                opts[k].append(dhcp6build_dns(i))
        elif k == DHCP6DOMAIN:
            opts[k] = []
            for i in v:
                opts[k].append(dhcp6build_domain(i))
        elif k == DHCP6VENDORCLASS:
            opts[k] = []
            for i in v:
                opts[k].append(dhcp6build_vendorclass(i['num'], i['desc']))
    return opts


def dhcp6build_ext(res):
    msgtype = res['msgtype']
    trid = res['trid']
    opts = dhcp6buildopts_ext(res['opts'])
    buf = dhcp6build(msgtype, trid, opts)
    if 'relay' in res:
        msgtype = res['relay']['msgtype']
        hopcount = res['relay']['hopcount']
        linkaddr = res['relay']['linkaddr']
        peeraddr = res['relay']['peeraddr']
        opts = {DHCP6RELAYMSG: buf}
        buf = dhcp6build_relay(msgtype, hopcount, linkaddr, peeraddr, opts)
    return buf
