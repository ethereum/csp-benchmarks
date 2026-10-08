// node circom/tests/secp256k1-circuits.cjs <artifact-root> <vectors.json> [points|straus|ecdsa|all]
// Compile ecdsa_32 and tests/secp256k1/{point_ops,straus} with Circom 2.2.3
// --O2 --r1cs --wasm --sym into same-named subdirectories.
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
const P = (1n << 256n) - (1n << 32n) - 977n;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const G = [0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n];
const mod = (x, m = P) => (x % m + m) % m;
function inv(x, m = P) {
    let a = mod(x, m), b = m, u = 1n, v = 0n;
    while (b) { const q = a / b; [a, b] = [b, a - q * b]; [u, v] = [v, u - q * v]; }
    assert.equal(a, 1n); return mod(u, m);
}
function add(a, b) {
    if (!a) return b; if (!b) return a;
    if (a[0] === b[0] && mod(a[1] + b[1]) === 0n) return null;
    const l = mod(a[0] === b[0] ? 3n*a[0]*a[0]*inv(2n*a[1]) : (b[1]-a[1])*inv(b[0]-a[0]));
    const x = mod(l*l-a[0]-b[0]); return [x, mod(l*(a[0]-x)-a[1])];
}
function mul(k, a = G) {
    k = mod(k, N); let out = null;
    while (k) { if (k & 1n) out = add(out, a); a = add(a, a); k >>= 1n; }
    return out;
}
const limbs = x => Array.from({ length: 4 }, (_, j) => ((x >> BigInt(64*j)) & 0xffffffffffffffffn).toString());
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
        const expected = [add(a, b), add(a, a)];
        const coordinates = expected.flatMap(p => encode(p).flat().map(BigInt));
        assert.deepEqual(result.witness.slice(1, 17), coordinates);
        assert.deepEqual(result.witness.slice(17, 19), expected.map(p => BigInt(!p)));
        // Mutate outputs and the selectors of each exceptional class:
        // tangent, cancellation and input infinity.
        await c.forge(result.bin, ['main.out[0][0][0]', 'main.out[1][1][0]',
            'main.outInf[0]', 'main.outInf[1]', 'main.add.tangent', 'main.add.cancel',
            'main.add.lambda[0]', 'main.add.slopeCheck.q[0]']);
        baseline = result;
    }
    for (const [key, value] of [['aInf', 2], ['bInf', 2], ['a', encode([P, 0n])], ['a', encode([0n, 0n])]]) {
        await assert.rejects(c.calculator.calculateWitness({ a: encode(G), b: encode(G), aInf: 0, bInf: 0, [key]: value }, true));
    }
    await assert.rejects(c.calculator.calculateWitness({ a: encode(G), b: encode(G), aInf: 1, bInf: 0 }, true));
    await c.forge(baseline.bin, ['main.add.xCheck.q[0]', 'main.add.yCheck.q[0]']);
    c.done();
}
async function straus() {
    const c = await circuit('straus');
    const D = mul(12345678901234567890n);
    const e = [(1n << 63n) + 123n, (1n << 62n) + 7n, (1n << 63n) + (1n << 40n) + 5n, (1n << 61n) + 99n];
    // A[j] = r[j]*a with e0 + r1*e1 + r2*e2 + r3*e3 = 0 (mod n).
    const r = [1n, 0x1234567n, 0xabcdef0123n];
    r.push(mod(-(e[0] + r[1]*e[1] + r[2]*e[2]) * inv(e[3], N), N));
    const inputs = a => ({ mag: e.map(String), A: r.map(k => encode(mul(k, a))) });
    // Construct an actual infinity accumulator at three different loop steps.
    // After consuming bits 63..i the accumulator is (2^(64-i)-1)*D plus the
    // prefixes of the scalars times A[j].
    for (const i of [63n, 62n, 40n]) {
        const offset = (1n << (64n-i)) - 1n;
        const coefficient = mod(r.reduce((sum, k, j) => sum + k*(e[j] >> i), 0n), N);
        const a = mul(mod(-offset*inv(coefficient, N), N), D);
        const result = await c.valid(inputs(a));
        assert.equal(c.value(result.witness, `main.loop.accInf[${i}]`), 1n);
        await c.forge(result.bin, [`main.loop.accInf[${i}]`, `main.loop.adder[${i-1n}].lambda[0]`]);
    }
    // T1 = O for the base -D, and T3 = T1 + A1 recovers a finite point.
    const result = await c.valid(inputs(mul(-1n, D)));
    assert.equal(c.value(result.witness, 'main.loop.TInf[1]'), 1n);
    assert.equal(c.value(result.witness, 'main.loop.TInf[3]'), 0n);
    // tab[1].cancel is linear in retained wires and removed by --O2.
    await c.forge(result.bin, ['main.loop.TInf[1]', 'main.loop.tab[1].tangent', 'main.loop.tab[3].lambda[0]']);
    // A table doubling: A0 = D makes T1 = 2D.
    const doubled = await c.valid(inputs(D));
    assert.equal(c.value(doubled.witness, 'main.loop.tab[1].tangent'), 1n);
    await c.forge(doubled.bin, ['main.loop.tab[1].tangent', 'main.loop.tab[1].lambda[0]']);
    const wrong = inputs(G); wrong.mag[1] = (e[1]+1n).toString();
    await assert.rejects(c.calculator.calculateWitness(wrong, true));
    c.done();
}
async function ecdsa() {
    const c = await circuit('ecdsa_32'); let baseline;
    // Run every vector before failing, so one report lists all rejected
    // valid signatures.
    const failures = [];
    let signDependentHits = 0;
    for (const v of JSON.parse(fs.readFileSync(vectorsFile, 'utf8'))) {
        try {
            if (v.expect === 'reject') await assert.rejects(c.calculator.calculateWitness(v.input, true), v.name);
            else {
                const result = await c.valid(v.input);
                if (v.name === 'basic') baseline = result;
                if (v.entry !== undefined) {
                    // The vector must reach its table entry as a doubling or O.
                    const hit = c.value(result.witness, `main.glv.loop.tab[${v.entry}].tangent`)
                        + c.value(result.witness, `main.glv.loop.TInf[${v.entry}]`);
                    if (v.sign_dependent) signDependentHits += Number(hit);
                    else assert.equal(hit, 1n, `${v.name}: T[${v.entry}] is an ordinary addition`);
                }
                // useFinalDouble is folded away by --O2; badAcc0[4] carries its value.
                assert.equal(c.value(result.witness, 'main.u1G.badAcc0[4]'), v.comb_final_double ? 1n : 0n,
                    `${v.name}: unexpected comb final-doubling flag`);
            }
            console.log(`ecdsa: ${v.name} ${v.expect} ok`);
        } catch (error) {
            failures.push(v.name);
            console.log(`ecdsa: ${v.name} ${v.expect} FAILED: ${String(error.message).split('\n')[0]}`);
        }
    }
    assert.deepEqual(failures, [], `failed vectors: ${failures.join(', ')}`);
    assert(signDependentHits > 0, 'no sign-dependent vector reached its table entry');
    assert(baseline);
    await c.forge(baseline.bin, ['main.r[0]', 'main.s[0]', 'main.msghash[0]', 'main.pubkey[0][0]',
        'main.sinv[0]', 'main.Rx[0]', 'main.Ry[0]', 'main.mag[0]', 'main.sgn[1]',
        'main.glv.loop.TInf[1]', 'main.glv.loop.tab[1].tangent', 'main.glv.loop.tab[1].lambda[0]',
        'main.glv.loop.tab[1].slopeCheck.q[0]', 'main.glv.loop.adder[0].lambda[0]',
        'main.glv.loop.adder[0].tangent', 'main.glv.loop.adder[0].xCheck.q[0]',
        'main.glv.loop.adder[0].yCheck.q[0]', 'main.glv.loop.accInf[1]']);
    c.done();
}
(async () => {
    assert(['points', 'straus', 'ecdsa', 'all'].includes(mode));
    if (mode === 'points' || mode === 'all') await points();
    if (mode === 'straus' || mode === 'all') await straus();
    if (mode === 'ecdsa' || mode === 'all') await ecdsa();
    process.exit(0);
})().catch(error => { console.error(error); process.exit(1); });
