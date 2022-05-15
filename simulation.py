import argparse
import random

parser = argparse.ArgumentParser()
parser.add_argument('-v', '--verbose', action='store_true', default=False)
parser.add_argument('--anum', type=int, default=2000)
parser.add_argument('--hnum', type=int, default=1000)
parser.add_argument('--snum', type=int, default=700)
parser.add_argument('-L', action='store_const', dest='aat', const='linear')
parser.add_argument('-R', action='store_const', dest='aat', const='random')
parser.add_argument('-d', action='store_const', dest='algo', const='ddelimit')
parser.add_argument('-r', action='store_const', dest='algo', const='rdelimit')
parser.add_argument('-s', action='store_const', dest='algo', const='sdelimit')
parser.add_argument('-w', '--window', type=int, default=3)
parser.add_argument('-c', '--count', type=int, default=64)
args = parser.parse_args()

verbose = args.verbose
anum = args.anum
hnum = args.hnum
snum = args.snum
aat = args.aat or 'random'
algo = args.algo or 'sdelimit'
window = args.window
count = args.count

sample = []

if aat == 'linear':
    sample = list(range(anum))
elif aat == 'random':
    sample = random.sample(range(2**48), anum)

sampleiter = iter(sample)

host = [next(sampleiter) for _ in range(hnum)]
shost = random.sample(host, snum)


def ping(h):
    res = h in shost
    if verbose:
        print(f'ping {h}: {"success" if res else "failed"}')
    return res


def rebind(h):
    res = 0 <= h <= 2**48 and h not in host
    if verbose:
        print(f'rebind {h}: {"success" if res else "failed"}')
    return res


def solicit():
    h = next(sampleiter)
    if verbose:
        print(f'solicit {h}')
    return h


def dllimit(l, u):
    h = (l + u) // 2
    if l >= u:
        return h
    if ping(h):
        return dllimit(l, h - 1)
    for i in range(max(h - window, l), min(h + window + 1, u + 1)):
        if i == h:
            continue
        if ping(i):
            return dllimit(l, i - 1)
    return dllimit(h + 1, u)


def dulimit(l, u):
    h = (l + u) // 2
    if l >= u:
        return h
    if ping(h):
        return dulimit(h + 1, u)
    for i in range(max(h - window, l), min(h + window + 1, u + 1)):
        if i == h:
            continue
        if ping(i):
            return dulimit(i + 1, u)
    return dulimit(l, h - 1)


def ddelimit():
    a, l, u = solicit(), 0, 2**64 - 1
    return dllimit(l, a), dulimit(a, u)


def rllimit(l, u):
    h = (l + u) // 2
    if l >= u:
        return h
    if rebind(h) or ping(h):
        return rllimit(l, h - 1)
    else:
        return rllimit(h + 1, u)


def rulimit(l, u):
    h = (l + u) // 2
    if l >= u:
        return h
    if rebind(h) or ping(h):
        return rulimit(h + 1, u)
    else:
        return rulimit(l, h - 1)


def rdelimit():
    a, l, u = solicit(), 0, 2**64 - 1
    return rllimit(l, a), rulimit(a, u)


def sdelimit():
    a = solicit()
    l, u = a, a
    for _ in range(count):
        a = solicit()
        l, u = min(l, a), max(u, a)
    d = (u - l) // count
    return l - d, u + d


l, u = 0, 0
if algo == 'ddelimit':
    l, u = ddelimit()
elif algo == 'rdelimit':
    l, u = rdelimit()
elif algo == 'sdelimit':
    l, u = sdelimit()

m = 0

if aat == 'linear':
    m = hnum
elif aat == 'random':
    m = 2**48 - 1

p1 = 1 - (abs(l) + abs(u - m)) / m

p2 = len(list(filter(lambda h: l <= h <= u, shost))) / len(shost)

print(f'{p1 * 100}%, {p2 * 100}%')
