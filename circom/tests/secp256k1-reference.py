import json
import random
import re
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes

import argparse

parser = argparse.ArgumentParser()
parser.add_argument('vectors', type=Path, help='output path for independently verified ECDSA vectors')
args = parser.parse_args()
SRC = Path(__file__).resolve().parents[1] / 'circuits/ecdsa'
P = (1 << 256) - (1 << 32) - 977
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
G = (0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
     0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
LAMBDA = 0x5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72
K0 = 12345678901234567890

def add(a, b):
    if a is None: return b
    if b is None: return a
    x, y = a; u, v = b
    if x == u and (y + v) % P == 0: return None
    slope = (3*x*x*pow(2*y, -1, P) if x == u else (v-y)*pow(u-x, -1, P)) % P
    w = (slope*slope-x-u) % P
    return w, (slope*(x-w)-y) % P

def mul(k, a=G):
    k %= N
    out = None
    while k:
        if k & 1: out = add(out, a)
        a = add(a, a); k >>= 1
    return out

def limbs(x, width=64, length=4):
    return [str((x >> (width*i)) & ((1 << width)-1)) for i in range(length)]

def check_sig(h, r, s, q):
    key = ec.EllipticCurvePublicNumbers(*q, ec.SECP256K1()).public_key()
    key.verify(utils.encode_dss_signature(r, s), h.to_bytes(32, 'big'), ec.ECDSA(utils.Prehashed(hashes.SHA256())))

vectors = []
# entry: the Straus table entry the vector makes exceptional (a doubling or
# O). sign_dependent: whether it does so depends on a decomposition sign.
def vector(name, d=1, nonce=1, h=0, high_s=False, **extra):
    q = mul(d); r = mul(nonce)[0] % N; s = pow(nonce, -1, N)*(h+r*d) % N
    if high_s: s = N-s
    custom(name, h, r, s, q, **extra)
    return r, s

def custom(name, h, r, s, q, **extra):
    check_sig(h, r, s, q)
    vectors.append({'name': name, 'expect': 'accept', **extra, 'input': {'r': limbs(r), 's': limbs(s), 'msghash': limbs(h), 'pubkey': [limbs(q[0]), limbs(q[1])]}})

def s_multiple(name, factor, entry, d=2, nonce=3):
    # S = [u2]Q = [r*d/s]G. Choose h so that r*d/s = factor*K0, i.e.
    # S = [factor]D, which enters the Straus table as A2 = -S and A3 = -phi(S).
    r = mul(nonce)[0] % N
    target = factor*K0 % N
    h = (r*nonce*d*pow(target, -1, N) - r*d) % N
    _, s = vector(name, d=d, nonce=nonce, h=h, entry=entry)
    assert r*d*pow(s, -1, N) % N == target

vector('basic', d=2, nonce=3, h=123)
vector('zero-prehash')
vector('high-s', d=2, nonce=3, h=123, high_s=True)
vector('hash-max', d=2, nonce=3, h=(1 << 256)-1)
# Public key Q = +-D: table entry T[1] = D + A0 adds D to +-D.
vector('sentinel-key', d=K0, nonce=3, h=123, entry=1)
vector('sentinel-key-negated', d=N-K0, nonce=3, h=123, entry=1)
vector('sentinel-key-other-nonce', d=K0, nonce=5, h=77, entry=1)
# phi(Q) = +-D: T[2] = D + A1.
vector('sentinel-key-phi', d=K0*pow(LAMBDA, -1, N) % N, nonce=3, h=123, entry=2)
vector('sentinel-key-phi-negated', d=-K0*pow(LAMBDA, -1, N) % N, nonce=3, h=123, entry=2)
# S = +-D: T[4] = D + A2; phi(S) = +-D: T[8] = D + A3.
s_multiple('sentinel-S', 1, 4)
s_multiple('sentinel-S-negated', -1, 4)
s_multiple('sentinel-S-phi', pow(LAMBDA, -1, N), 8)
s_multiple('sentinel-S-phi-negated', -pow(LAMBDA, -1, N), 8)
# D + A0 = +-A1 for one decomposition sign: T[3] = T[1] + A1.
for a in (1, -1):
    for b in (1, -1):
        vector(f'sentinel-key-combo-{a}-{b}', d=K0*pow(a*LAMBDA+b, -1, N) % N, nonce=3, h=123,
               entry=3, sign_dependent=True)
# With s = 1, u1 = h. h = k_bad makes the final comb addition a doubling
# (comb_fixed.circom, section 3a); Q is chosen so that R = [2]G.
KBAD = 0xe00000000000000000000000000000014551231950b75fc4402da1732fc9bebf
rr = mul(2)[0] % N
custom('comb-final-doubling', KBAD, rr, 1, mul((2-KBAD)*pow(rr, -1, N)), comb_final_double=True)
rng = random.Random(309)
for i in range(4): vector(f'random-{i}', rng.randrange(1, N), rng.randrange(1, N), rng.randrange(1, 1 << 256))

base = vectors[0]['input']
def invalid(name, key, value):
    data = json.loads(json.dumps(base)); data[key] = value
    vectors.append({'name': name, 'expect': 'reject', 'input': data})
invalid('r-zero', 'r', limbs(0)); invalid('s-zero', 's', limbs(0))
invalid('r-n', 'r', limbs(N)); invalid('s-n', 's', limbs(N))
invalid('changed-r', 'r', limbs(int(base['r'][0])+1 + sum(int(base['r'][i]) << (64*i) for i in range(1, 4))))
invalid('wrong-prehash', 'msghash', limbs(124))
invalid('invalid-key-zero', 'pubkey', [limbs(0), limbs(0)])
invalid('noncanonical-key-p', 'pubkey', [limbs(P), limbs(0)])
invalid('oversized-key-limb', 'pubkey', [[str(1 << 64)]+base['pubkey'][0][1:], base['pubkey'][1]])

args.vectors.write_text(json.dumps(vectors, indent=2))
print(f'{len(vectors)} vectors written; all {sum(v["expect"] != "reject" for v in vectors)} valid signatures independently verified by cryptography/OpenSSL', flush=True)

def getter(name):
    t = (SRC/'glv4_straus.circom').read_text()
    body = re.search(r'function '+name+r'\(\)\s*\{(.*?)return ret;', t, re.S)[1]
    vals = {int(i): int(v) for i, v in re.findall(r'ret\[(\d+)\] = (\d+);', body)}
    return sum(vals[i] << (64*i) for i in range(4))
D = (getter('get_glv4_sentinel_x'), getter('get_glv4_sentinel_y'))
C = (getter('get_glv4_target_x'), getter('get_glv4_target_y'))
assert D == mul(K0)
assert C == mul((1 << 64)-1, D)
print('Straus secp256k1 sentinel D and terminal constant C match independent EC arithmetic', flush=True)

bad = []
for top in range(1, 4096, 2):
    # Before the final window, |partial| < 2^252. Solve partial = top*2^252 (mod n).
    w = top*(1 << 252) % N
    for partial in (w, w-N):
        if abs(partial) < 1 << 252:
            kodd = partial + top*(1 << 252)
            if 1 <= kodd < 2*N and kodd % 2:
                bad.append(kodd)
assert set(bad) == {KBAD}, [hex(x) for x in bad]
t = (SRC/'comb_fixed.circom').read_text()
vals = {int(i): int(v) for i, v in re.findall(r'badEq0\[(\d)\]\.in <== fold\.out\[\d\] - (\d+);', t)}
assert sum(vals[i] << (64*i) for i in range(5)) == KBAD
print('Final comb equal-point case: exhaustive odd top-digit search reproduces the k_bad in comb_fixed.circom', flush=True)
