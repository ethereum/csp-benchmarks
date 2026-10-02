// node circom/tests/p256-circuits.cjs <artifact-root> <vectors.json> [points|modulo|straus|ecdsa|all]
// Compile ecdsa_p256_32 and tests/p256/{point_ops,quad_mod,straus} with
// Circom 2.2.3 --O2 --r1cs --wasm --sym into same-named subdirectories.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createRequire } = require('node:module');
const { execFileSync } = require('node:child_process');
let resolveFrom = require;
try { require.resolve('snarkjs'); } catch {
    resolveFrom = createRequire(path.join(execFileSync('npm', ['root', '-g'], { encoding: 'utf8' }).trim(), 'snarkjs/package.json'));
}
const snarkjs = resolveFrom('snarkjs');
const quiet = { info() {}, debug() {}, warn() {}, error() {} };
const root = path.resolve(process.argv[2]);
const vectorsFile = process.argv[3];
const mode = process.argv[4] || 'all';
const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const G = [0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
    0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n];
const mod = (x, m = P) => (x % m + m) % m;
function inv(x, m = P) {
    let a = mod(x, m), b = m, u = 1n, v = 0n;
    while (b) { const q = a / b; [a, b] = [b, a - q * b]; [u, v] = [v, u - q * v]; }
    assert.equal(a, 1n); return mod(u, m);
}
function add(a, b) {
    if (!a) return b; if (!b) return a;
    if (a[0] === b[0] && mod(a[1] + b[1]) === 0n) return null;
    const l = mod(a[0] === b[0] ? (3n*a[0]*a[0]-3n)*inv(2n*a[1]) : (b[1]-a[1])*inv(b[0]-a[0]));
    const x = mod(l*l-a[0]-b[0]); return [x, mod(l*(a[0]-x)-a[1])];
}
function mul(k, a = G) {
    k = mod(k, N); let out = null;
    while (k) { if (k & 1n) out = add(out, a); a = add(a, a); k >>= 1n; }
    return out;
}
const limbs = x => Array.from({ length: 8 }, (_, j) => ((x >> BigInt(32*j)) & 0xffffffffn).toString());
const encode = a => (a || [0n, 0n]).map(limbs);
function flip(bin, wire) {
    const copy = Buffer.from(bin); let offset = 12, width;
    while (offset < copy.length) {
        const type = copy.readUInt32LE(offset), length = Number(copy.readBigUInt64LE(offset+4)); offset += 12;
        if (type === 1) width = copy.readUInt32LE(offset);
        if (type === 2) { copy[offset + width*wire] ^= 1; return copy; }
        offset += length;
    }
    throw Error('missing witness section');
}
async function circuit(name) {
    const dir = path.join(root, name), js = path.join(dir, `${name}_js`);
    const calculator = await require(path.join(js, 'witness_calculator.js'))(fs.readFileSync(path.join(js, `${name}.wasm`)));
    const wires = new Map(fs.readFileSync(path.join(dir, `${name}.sym`), 'utf8').trim().split('\n').map(line => {
        const fields = line.split(','); return [fields[3], Number(fields[1])];
    }));
    const r1cs = path.join(dir, `${name}.r1cs`), output = path.join(dir, 'regression.wtns');
    let checked = 0, forged = 0;
    return {
        calculator, wires,
        async valid(input) {
            const witness = await calculator.calculateWitness(input, true);
            const bin = Buffer.from(await calculator.calculateWTNSBin(input, true));
            fs.writeFileSync(output, bin);
            assert(await snarkjs.wtns.check(r1cs, output, quiet), `${name}: generated witness fails R1CS`);
            checked++; return { witness, bin };
        },
        async forge(bin, names) {
            for (const name of names) {
                const wire = wires.get(name);
                assert(wire > 0, `missing retained wire ${name}`);
                fs.writeFileSync(output, flip(bin, wire));
                assert.equal(await snarkjs.wtns.check(r1cs, output, quiet), false, `forged ${name} accepted`);
                forged++;
            }
        },
        value(witness, name) { const wire = wires.get(name); assert(wire >= 0, `missing ${name}`); return witness[wire]; },
        done() { fs.rmSync(output, { force: true }); console.log(`${name}: ${checked} R1CS-valid witnesses; ${forged} rejected wire mutations`); }
    };
}
async function points() {
    const c = await circuit('point_ops');
    let baseline;
    const cases = [[null, null], [null, G], [G, null]];
    for (const a of [1n, 7n]) for (const b of [-4n, -2n, -1n, 1n, 2n, 4n, 13n]) cases.push([mul(a), mul(a*b)]);
    for (let i = 1n; i <= 6n; i++) cases.push([mul(i*12345n), mul(i*67891n)]);
    for (const [a, b] of cases) {
        const result = await c.valid({ a: encode(a), b: encode(b), aInf: Number(!a), bInf: Number(!b) });
        const expected = [add(a, b), add(mul(2n, a), b), add(mul(4n, a), b)];
        const coordinates = expected.flatMap(p => encode(p).flat().map(BigInt));
        assert.deepEqual(result.witness.slice(1, 49), coordinates);
        assert.deepEqual(result.witness.slice(49, 52), expected.map(p => BigInt(!p)));
        // Mutate outputs and the selectors in each exceptional class, including
        // cancellation, second-stage infinity, tangent, and input infinity.
        await c.forge(result.bin, ['main.out[0][0][0]', 'main.outInf[1]',
            'main.fused.cancel', 'main.fused.tangent1', 'main.fused.zeroOut',
            'main.quad.equalY', 'main.quad.sameFiniteX', 'main.quad.zeroOut',
            'main.add.lambda[0]', 'main.add.tangent', 'main.add.slopeCheck.c.q[0]']);
        baseline = result;
    }
    for (const [key, value] of [['aInf', 2], ['bInf', 2], ['a', encode([P, 0n])], ['a', encode([0n, 0n])]]) {
        await assert.rejects(c.calculator.calculateWitness({ a: encode(G), b: encode(G), aInf: 0, bInf: 0, [key]: value }, true));
    }
    await assert.rejects(c.calculator.calculateWitness({ a: encode(G), b: encode(G), aInf: 1, bInf: 0 }, true));
    await c.forge(baseline.bin, ['main.fused.l1[0]', 'main.fused.l2[0]',
        'main.quad.l0[0]', 'main.fused.slopeCheck2.c.q[0]', 'main.quad.signCheck.c.q[0]', 'main.quad.slopeCheck1.c.q[0]']);
    c.done();
}
function power(x, n) {
    let out = 1n;
    while (n) { if (n & 1n) out = mod(out*x); x = mod(x*x); n >>= 1n; }
    return out;
}
async function moduloCoordinates() {
    const c = await circuit('quad_mod');
    let a;
    for (let x = 0n; !a; x++) {
        const rhs = mod(x*x*x-3n*x+0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn);
        const y = power(rhs, (P+1n)/4n);
        if (mod(y*y) === rhs) a = [x, y];
    }
    for (const offset of [0n, P]) for (const b of [G, null, mul(2n, a), mul(-2n, a), mul(-4n, a)]) {
        const represented = [a[0]+offset, a[1]];
        assert(represented[0] < 1n << 256n);
        const result = await c.valid({ a: encode(represented), b: encode(b), aInf: 0, bInf: Number(!b) });
        const expected = add(mul(4n, a), b);
        const decoded = [0, 1].map(coord => mod(result.witness.slice(1+8*coord, 9+8*coord)
            .reduce((sum, limb, j) => sum+(limb << BigInt(32*j)), 0n)));
        assert.deepEqual(decoded, expected || [0n, 0n]);
        assert.equal(result.witness[17], BigInt(!expected));
        await c.forge(result.bin, ['main.out[0][0]', 'main.quad.equalY']);
    }
    c.done();
}
async function straus() {
    const c = await circuit('straus');
    const D = mul(12345678901234567890n);
    const e0 = (1n << 127n) + 123n, e1 = (1n << 126n) + 7n;
    const ratio = mod(-e0 * inv(e1, N), N);
    const inputs = a => ({ mag: [e0.toString(), e1.toString()], A: [encode(a), encode(mul(ratio, a))] });
    // Construct an actual infinity accumulator at three different loop steps.
    // Prefixes consume the high two-bit digits, with sentinel multiplier
    // 1+4+...+4^(number of consumed digits-1).
    for (const i of [63n, 62n, 40n]) {
        const count = 64n-i;
        const offset = ((1n << (2n*count))-1n)/3n;
        const coefficient = mod((e0 >> (2n*i)) + ratio*(e1 >> (2n*i)), N);
        const a = mul(mod(-offset*inv(coefficient, N), N), D);
        const result = await c.valid(inputs(a));
        assert.equal(c.value(result.witness, `main.loop.accInf[${i}]`), 1n);
        await c.forge(result.bin, [`main.loop.accInf[${i}]`, 'main.loop.qadd[0].l2[0]']);
    }
    // T1=O, and T2 recovers a finite point, for the base -D.
    const result = await c.valid(inputs(mul(-1n, D)));
    assert.equal(c.value(result.witness, 'main.loop.TInf[1]'), 1n);
    assert.equal(c.value(result.witness, 'main.loop.TInf[2]'), 0n);
    await c.forge(result.bin, ['main.loop.TInf[1]']);
    await c.valid({ mag: ['0', '0'], A: [encode(G), encode(G)] });
    const wrong = inputs(G); wrong.mag[1] = (e1+1n).toString();
    await assert.rejects(c.calculator.calculateWitness(wrong, true));
    c.done();
}
async function ecdsa() {
    const c = await circuit('ecdsa_p256_32'); let baseline;
    for (const v of JSON.parse(fs.readFileSync(vectorsFile, 'utf8'))) {
        if (v.expect === 'reject') await assert.rejects(c.calculator.calculateWitness(v.input, true), v.name);
        else {
            const result = await c.valid(v.input);
            if (v.name === 'basic') baseline = result;
        }
        console.log(`ecdsa: ${v.name} ${v.expect}`);
    }
    assert(baseline);
    await c.forge(baseline.bin, ['main.r[0]', 'main.s[0]', 'main.msghash[0]', 'main.pubkey[0][0]',
        'main.sinv[0]', 'main.Rx[0]', 'main.Ry[0]', 'main.mag[0]', 'main.sgn[1]',
        'main.glv.loop.qadd[0].l1[0]', 'main.glv.loop.qadd[0].l2[0]',
        'main.glv.loop.qadd[0].slopeCheck2.c.q[0]', 'main.glv.loop.qadd[0].sameFiniteX',
        'main.glv.loop.qadd[0].zeroOut', 'main.glv.loop.qadd[0].equalY',
        'main.glv.loop.qadd[0].signCheck.c.q[0]', 'main.glv.loop.qadd[0].l0[0]',
        'main.glv.loop.tab[1].lambda[0]', 'main.glv.loop.tab[1].tangent',
        'main.glv.loop.tab[1].slopeCheck.c.q[0]']);
    c.done();
}
(async () => {
    assert(['points', 'modulo', 'straus', 'ecdsa', 'all'].includes(mode));
    if (mode === 'points' || mode === 'all') await points();
    if (mode === 'modulo' || mode === 'all') await moduloCoordinates();
    if (mode === 'straus' || mode === 'all') await straus();
    if (mode === 'ecdsa' || mode === 'all') await ecdsa();
    process.exit(0);
})().catch(error => { console.error(error); process.exit(1); });
