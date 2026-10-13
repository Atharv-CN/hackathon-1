import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { decryptPackage, encryptPackage, fromBase64, makeBackup, makeRecipient, restoreBackup, toBase64 } from '../src/crypto.js';

const golden = JSON.parse(fs.readFileSync(new URL('./golden_package_v1.json', import.meta.url), 'utf8'));
const seed = Uint8Array.from(golden.private_key_seed_hex.match(/../g), hex => parseInt(hex, 16));
const keys = ml_kem768.keygen(seed);
const receiver = { seed, ...keys };

test('opens the Python QShield v1 golden package', async () => {
  const result = await decryptPackage(fromBase64(golden.package_base64), receiver);
  assert.equal(result.filename, golden.filename);
  assert.equal(new TextDecoder().decode(result.bytes), golden.plaintext_utf8);
});

test('new browser packages round trip and reject changed contents', async () => {
  const generated = makeRecipient();
  const file = new TextEncoder().encode('private example');
  const packageBytes = await encryptPackage(file, 'note.txt', toBase64(generated.publicKey));
  const result = await decryptPackage(packageBytes, generated);
  assert.equal(result.filename, 'note.txt');
  assert.deepEqual(result.bytes, file);
  packageBytes[packageBytes.length - 1] ^= 1;
  await assert.rejects(decryptPackage(packageBytes, generated), /integrity/);
});

test('encrypted backup restores the same key; wrong password fails', async () => {
  const generated = makeRecipient();
  const backup = await makeBackup(generated, 'a strong unique password');
  const restored = await restoreBackup(backup, 'a strong unique password');
  assert.deepEqual(restored.publicKey, generated.publicKey);
  await assert.rejects(restoreBackup(backup, 'wrong password'), /Wrong backup password/);
  assert.ok(!backup.includes(toBase64(generated.seed)));
});
