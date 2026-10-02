import ast
import json
import math
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
P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
     0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)

def add(a, b):
    if a is None: return b
    if b is None: return a
    x, y = a; u, v = b
    if x == u and (y + v) % P == 0: return None
    slope = ((3*x*x-3)*pow(2*y, -1, P) if x == u else (v-y)*pow(u-x, -1, P)) % P
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
    key = ec.EllipticCurvePublicNumbers(*q, ec.SECP256R1()).public_key()
    key.verify(utils.encode_dss_signature(r,s), h.to_bytes(32,'big'), ec.ECDSA(utils.Prehashed(hashes.SHA256())))

vectors = []
def vector(name, d=1, nonce=1, h=0, high_s=False):
    q = mul(d); r = mul(nonce)[0] % N; s = pow(nonce, -1, N)*(h+r*d) % N
    if high_s: s = N-s
    custom(name,h,r,s,q)

def custom(name,h,r,s,q):
    check_sig(h,r,s,q)
    vectors.append({'name':name,'expect':'accept','input':{'r':limbs(r),'s':limbs(s),'msghash':limbs(h),'pubkey':[limbs(q[0]),limbs(q[1])]}})

vector('zero-prehash')
vector('basic',d=2,nonce=3,h=123)
vector('high-s',d=2,nonce=3,h=123,high_s=True)
vector('hash-equals-n',d=2,nonce=3,h=N)
vector('hash-n-plus-1',d=2,nonce=3,h=N+1)
vector('hash-max',d=2,nonce=3,h=(1<<256)-1)
vector('negative-nonce',d=N-1,nonce=N-1,h=123)
vector('sentinel-key',d=12345678901234567890,nonce=3,h=123)
for factor in [-1, 2, -2, 3, -3]:
    vector(f'sentinel-key-factor-{factor}',d=12345678901234567890*pow(factor,-1,N)%N,nonce=3,h=123)
custom('equal-x-subtraction',1,G[0],1,mul(-2*pow(G[0],-1,N)))
KBAD=0xe0000000ffffffff00000000000000004319055258e8617b0c46353d039cdaaf
rr=mul(2)[0]%N
custom('comb-final-doubling',KBAD,rr,1,mul((2-KBAD)*pow(rr,-1,N)))
for x in range(N,N+50):
    y2=(x*x*x-3*x+B)%P
    y=pow(y2,(P+1)//4,P)
    if y*y%P == y2:
        R=(x,y); r=x-N
        if r: break
custom('R-x-above-n',1,r,1,mul(pow(r,-1,N),add(R,(G[0],P-G[1]))))
rng=random.Random(308)
for i in range(8): vector(f'random-{i}',rng.randrange(1,N),rng.randrange(1,N),rng.randrange(1,1<<256))

base = vectors[1]['input']
def invalid(name,key,value):
    data=json.loads(json.dumps(base)); data[key]=value
    vectors.append({'name':name,'expect':'reject','input':data})
invalid('r-zero','r',limbs(0)); invalid('s-zero','s',limbs(0))
invalid('r-n','r',limbs(N)); invalid('s-n','s',limbs(N))
invalid('changed-r','r',limbs(int(base['r'][0])+1 + sum(int(base['r'][i])<<(64*i) for i in range(1,4))))
invalid('wrong-prehash','msghash',limbs(124))
invalid('invalid-key-zero','pubkey',[limbs(0),limbs(0)])
invalid('noncanonical-key-p','pubkey',[limbs(P),limbs(0)])
invalid('oversized-key-limb','pubkey',[[str(1<<64)]+base['pubkey'][0][1:],base['pubkey'][1]])
invalid('oversized-r-limb','r',[str(1<<64)]+base['r'][1:])
invalid('oversized-hash-limb','msghash',[str(1<<64)]+base['msghash'][1:])

args.vectors.write_text(json.dumps(vectors,indent=2))
print(f'{len(vectors)} vectors written; all {sum(v["expect"]!="reject" for v in vectors)} valid signatures independently verified by cryptography/OpenSSL',flush=True)

text=(SRC/'comb_table_p256.circom').read_text()
chunks=re.findall(r'function p256_comb_table_(\d+)\(\)\s*\{\s*var t\[2048\]\[8\] = (\[.*?\]);',text,re.S)
assert len(chunks)==22
count=0
for wi, chunk in chunks:
    wi=int(wi); table=ast.literal_eval(chunk)
    expected=mul(1<<(12*wi)); step=add(expected,expected)
    for row in table:
        point=tuple(sum(row[4*c+j]<<(64*j) for j in range(4)) for c in range(2))
        assert point == expected, (wi,count)
        assert 0 <= point[0] < P and 0 <= point[1] < P
        assert (point[1]*point[1]-point[0]**3+3*point[0]-B)%P == 0
        expected=add(expected,step); count+=1
print(f'All {count} comb table points equal their documented P-256 multiples, canonical/on-curve',flush=True)

text=(SRC/'p256_utils.circom').read_text()
table=ast.literal_eval(re.search(r'var T\[22\]\[8\] = (\[.*?\]);',text,re.S)[1])
for i,row in enumerate(table): assert (sum(v<<(32*j) for j,v in enumerate(row))-(1<<(32*i)))%P == 0
print('All 22 fast-reduction rows checked modulo the standard P-256 prime',flush=True)

for regs,m,shift,kq,M,length,g,qbits in [(15,69,40,2,74,11,6,41),(22,104,78,3,112,12,5,79),(22,102,76,3,110,12,5,77)]:
    # Independent bounds treating every signed input coefficient as adversarial.
    bounds=[sum(abs(table[i][j]) for i in range(regs))*((1<<m)-1) for j in range(8)]
    bound=sum(v<<(32*j) for j,v in enumerate(bounds))
    offset=P<<shift
    assert offset > bound
    assert (offset+bound)//P < 1<<qbits
    pl=[(P>>(32*j))&((1<<32)-1) for j in range(8)]
    maxqp=[sum(((1<<32)-1)*pl[j] for j in range(8) if 0<=i-j<kq) for i in range(kq+7)]
    diffbound=[maxqp[i]+bounds[i]+(pl[i]<<shift) if i<8 else maxqp[i] for i in range(kq+7)]
    assert all(v < 1<<(M-1) for v in diffbound)
    MG=M+32*(g-1)+1
    assert MG+3<=253
    print(f'mod-p check ({regs},{m}): positivity, {qbits}-bit quotient, {M}-bit coefficient and MG={MG} field bounds pass',flush=True)

# Bounds for the implicit first-doubling y registers and their tangent
# product. These are integer coefficient bounds before reduction modulo p.
limb_max = (1 << 32) - 1
product_max = 8 * limb_max**2
y_register_max = product_max + limb_max
lambda_y_max = 8 * limb_max * y_register_max
assert y_register_max < (1 << 67) + (1 << 32)
assert 2 * lambda_y_max + 3 * product_max + 3 < 1 << 104
assert 4 * product_max + 2 * limb_max < 1 << 69
assert max(3 * product_max + 3, product_max + 3 * limb_max, product_max + 2 * limb_max) < 1 << 69
print('Unified complete addition: disjoint slope, x and y residual 2^69 bounds pass', flush=True)
print('Implicit doubling: signed y registers, cubic tangent 2^104 bound and quadratic 2^69 bounds pass', flush=True)

def decompose(s):
    r0,r1=N,s; t0,t1=0,1
    while r1>math.isqrt(N):
        q=r0//r1; r0,r1=r1,r0-q*r1; t0,t1=t1,t0-q*t1
    assert 0<abs(t1)<1<<128 and 0<=r1<1<<128 and (r1-s*t1)%N == 0
    return r1,t1
for s in [1,2,math.isqrt(N),math.isqrt(N)+1,1<<128,N-1]+[rng.randrange(1,N) for _ in range(20000)]: decompose(s)
print('Truncated Euclid: 20,006 boundary/random scalar decompositions satisfy modular relation and 128-bit bounds',flush=True)

def getter(name):
    t=(SRC/'fake_glv2_straus.circom').read_text()
    body=re.search(r'function '+name+r'\(\)\s*\{(.*?)return ret;',t,re.S)[1]
    vals={int(i):int(v) for i,v in re.findall(r'ret\[(\d+)\] = (\d+);',body)}
    return sum(vals[i]<<(32*i) for i in range(8))
D=(getter('get_glv2_sentinel_x'),getter('get_glv2_sentinel_y'))
C=(getter('get_glv2_target_x'),getter('get_glv2_target_y'))
assert D==mul(12345678901234567890)
assert C==mul(((1<<128)-1)//3,D)
print('Straus P-256 sentinel D and 4-ary terminal constant C match independent EC arithmetic',flush=True)

bad=[]
for top in range(1,4096,2):
    # Before final window, |partial| < 2^252. Solve partial=top*2^252 (mod n).
    w=top*(1<<252)%N
    for partial in (w,w-N):
        if abs(partial)<1<<252:
            kodd=partial+top*(1<<252)
            if 1<=kodd<2*N and kodd%2:
                bad.append(kodd)
assert set(bad)=={KBAD}, [hex(x) for x in bad]
print('Final comb equal-point case exhaustive odd top-digit search reproduces hardcoded k_bad',flush=True)
