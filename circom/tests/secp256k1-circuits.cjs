// node circom/tests/secp256k1-circuits.cjs <artifact-root> <vectors.json> [ecdsa|all]
// Compile ecdsa_32 with Circom 2.2.3 --O2 --r1cs --wasm --sym into a
// same-named subdirectory.
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
async function ecdsa() {
    const c = await circuit('ecdsa_32'); let baseline;
    // Run every vector before failing, so one report lists all rejected
    // valid signatures.
    const failures = [];
    for (const v of JSON.parse(fs.readFileSync(vectorsFile, 'utf8'))) {
        try {
            if (v.expect === 'reject') await assert.rejects(c.calculator.calculateWitness(v.input, true), v.name);
            else {
                const result = await c.valid(v.input);
                if (v.name === 'basic') baseline = result;
            }
            console.log(`ecdsa: ${v.name} ${v.expect} ok`);
        } catch (error) {
            failures.push(v.name);
            console.log(`ecdsa: ${v.name} ${v.expect} FAILED: ${String(error.message).split('\n')[0]}`);
        }
    }
    assert.deepEqual(failures, [], `failed vectors: ${failures.join(', ')}`);
    assert(baseline);
    await c.forge(baseline.bin, ['main.r[0]', 'main.s[0]', 'main.msghash[0]', 'main.pubkey[0][0]',
        'main.sinv[0]', 'main.Rx[0]', 'main.Ry[0]', 'main.mag[0]', 'main.sgn[1]']);
    c.done();
}
(async () => {
    assert(['ecdsa', 'all'].includes(mode));
    if (mode === 'ecdsa' || mode === 'all') await ecdsa();
    process.exit(0);
})().catch(error => { console.error(error); process.exit(1); });
