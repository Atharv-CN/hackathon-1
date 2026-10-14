import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 as sha256Sync } from '@noble/hashes/sha2.js';

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const KDF_LABEL = encoder.encode('QShield v1: ML-KEM-768 + HKDF-SHA256 + AES-256-GCM');
const BACKUP_AAD = encoder.encode('QShield browser private key backup v1');
export const MAX_FILE_SIZE = 25 * 1024 * 1024;

function join(...arrays) {
  const out = new Uint8Array(arrays.reduce((size, part) => size + part.length, 0));
  let offset = 0;
  for (const part of arrays) { out.set(part, offset); offset += part.length; }
  return out;
}

function equal(a, b) {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a[i] ^ b[i];
  return difference === 0;
}

function random(size) { return crypto.getRandomValues(new Uint8Array(size)); }

export function toBase64(bytes) {
  let raw = '';
  for (let i = 0; i < bytes.length; i += 8192) raw += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return btoa(raw);
}

export function fromBase64(text) {
  const normalized = text.replace(/\s/g, '').replace(/-/g, '+').replace(/_/g, '/');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) throw new Error('Invalid base64 value.');
  return Uint8Array.from(atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=')), c => c.charCodeAt(0));
}

function safeFilename(name) {
  const value = String(name).replace(/\0/g, '').replace(/\\/g, '/').split('/').pop().trim();
  return value && value !== '.' && value !== '..' ? value : 'decrypted_file';
}

function checkedPublicKey(text) {
  let key;
  try { key = fromBase64(text); } catch { throw new Error('The public key is not valid base64.'); }
  if (key.length !== 1184) throw new Error('The receiver public key must contain 1184 bytes.');
  return key;
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

export async function publicFingerprint(text) {
  return [...await sha256(checkedPublicKey(text))].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

export function makeRecipient() {
  const seed = random(64);
  const { publicKey, secretKey } = ml_kem768.keygen(seed);
  return { seed, publicKey, secretKey };
}

async function aesKey(sharedSecret, header) {
  const raw = hkdf(sha256Sync, sharedSecret, new Uint8Array(32),
    join(KDF_LABEL, new Uint8Array([0]), header), 32);
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

export async function encryptPackage(fileBytes, filename, publicText) {
  if (fileBytes.length > MAX_FILE_SIZE) throw new Error('Choose a file no larger than 25 MB.');
  const publicKey = checkedPublicKey(publicText);
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);
  const fingerprint = await sha256(publicKey);
  const header = join(encoder.encode('QSHK'), new Uint8Array([1, 1]), fingerprint, cipherText);
  const key = await aesKey(sharedSecret, header);
  const metadata = encoder.encode(JSON.stringify({
    created_utc: new Date().toISOString().replace('.000Z', '+00:00').replace(/\.\d{3}Z$/, '+00:00'),
    filename: safeFilename(filename), original_size: fileBytes.length,
  }));
  const prefix = new Uint8Array(9);
  prefix.set(encoder.encode('QSHD'));
  prefix[4] = 1;
  new DataView(prefix.buffer).setUint32(5, metadata.length, false);
  const nonce = random(12);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: join(prefix, metadata), tagLength: 128 },
    key, fileBytes,
  ));
  return join(header, prefix, nonce, metadata, ciphertext);
}

export async function decryptPackage(packageBytes, recipient) {
  const data = new Uint8Array(packageBytes);
  if (data.length < 1126 + 9 + 12 + 16 || decoder.decode(data.subarray(0, 4)) !== 'QSHK' || data[4] !== 1 || data[5] !== 1) {
    throw new Error('This is not a supported QShield package.');
  }
  const fingerprint = await sha256(recipient.publicKey);
  if (!equal(data.subarray(6, 38), fingerprint)) throw new Error('This package belongs to a different receiver key.');
  const header = data.subarray(0, 1126);
  const secret = ml_kem768.decapsulate(data.subarray(38, 1126), recipient.secretKey);
  const key = await aesKey(secret, header);
  const prefix = data.subarray(1126, 1135);
  if (decoder.decode(prefix.subarray(0, 4)) !== 'QSHD' || prefix[4] !== 1) throw new Error('The encrypted file format is invalid.');
  const metaLength = new DataView(prefix.buffer, prefix.byteOffset, prefix.byteLength).getUint32(5, false);
  if (metaLength > 65536 || data.length < 1135 + 12 + metaLength + 16) throw new Error('The package is damaged.');
  const nonce = data.subarray(1135, 1147);
  const metadata = data.subarray(1147, 1147 + metaLength);
  let plaintext;
  try {
    plaintext = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: join(prefix, metadata), tagLength: 128 },
      key, data.subarray(1147 + metaLength),
    ));
  } catch { throw new Error('Package integrity check failed. The key or package is wrong or damaged.'); }
  try {
    const info = JSON.parse(decoder.decode(metadata));
    if (!info || typeof info.filename !== 'string' || info.original_size !== plaintext.length) throw new Error();
    return { filename: safeFilename(info.filename), bytes: plaintext };
  } catch { throw new Error('The package metadata is invalid.'); }
}

async function passwordKey(password, salt, usages) {
  const material = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 310000 },
    material, { name: 'AES-GCM', length: 256 }, false, usages,
  );
}

export async function makeBackup(recipient, password) {
  if (password.length < 12) throw new Error('Choose a backup password of at least 12 characters.');
  const salt = random(16);
  const nonce = random(12);
  const key = await passwordKey(password, salt, ['encrypt']);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: BACKUP_AAD, tagLength: 128 },
    key, recipient.seed,
  ));
  return JSON.stringify({ format: 'qshield-browser-key', version: 1, kdf: 'PBKDF2-SHA256', iterations: 310000,
    salt: toBase64(salt), nonce: toBase64(nonce), ciphertext: toBase64(ciphertext) }, null, 2);
}

export async function restoreBackup(text, password) {
  let backup;
  try { backup = JSON.parse(text); } catch { throw new Error('The backup file is not valid JSON.'); }
  if (backup?.format !== 'qshield-browser-key' || backup.version !== 1 || backup.kdf !== 'PBKDF2-SHA256' || backup.iterations !== 310000) {
    throw new Error('This is not a supported QShield browser key backup.');
  }
  let salt, nonce, ciphertext;
  try { salt = fromBase64(backup.salt); nonce = fromBase64(backup.nonce); ciphertext = fromBase64(backup.ciphertext); }
  catch { throw new Error('The backup file is damaged.'); }
  if (salt.length !== 16 || nonce.length !== 12 || ciphertext.length !== 80) throw new Error('The backup file is damaged.');
  const key = await passwordKey(password, salt, ['decrypt']);
  let seed;
  try { seed = new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: BACKUP_AAD, tagLength: 128 }, key, ciphertext,
  )); } catch { throw new Error('Wrong backup password or damaged backup.'); }
  if (seed.length !== 64) throw new Error('The backup file is damaged.');
  const { publicKey, secretKey } = ml_kem768.keygen(seed);
  return { seed, publicKey, secretKey };
}
