import './style.css';
import { MAX_FILE_SIZE, decryptPackage, encryptPackage, makeBackup, makeRecipient, publicFingerprint, restoreBackup, toBase64 } from './crypto.js';

const el = id => document.getElementById(id);
let recipient = null;
let encryptedUrl = null;
let decryptedUrl = null;

function message(id, text, error = false) {
  const target = el(id);
  target.textContent = text;
  target.classList.toggle('error', error);
  target.hidden = !text;
}

function download(id, label, bytes, filename, mime) {
  const target = el(id);
  if (id === 'encrypted-download' && encryptedUrl) URL.revokeObjectURL(encryptedUrl);
  if (id === 'decrypted-download' && decryptedUrl) URL.revokeObjectURL(decryptedUrl);
  const url = URL.createObjectURL(new Blob([bytes], { type: mime }));
  if (id === 'encrypted-download') encryptedUrl = url;
  else if (id === 'decrypted-download') decryptedUrl = url;
  target.replaceChildren();
  const link = document.createElement('a');
  link.className = 'download';
  link.href = url;
  link.download = filename;
  link.textContent = label;
  target.append(link);
  target.hidden = false;
}

async function showRecipient() {
  el('receiver-keys').hidden = false;
  el('public-key').value = toBase64(recipient.publicKey).replace(/\+/g, '-').replace(/\//g, '_');
  el('fingerprint').textContent = await publicFingerprint(el('public-key').value);
}

async function run(button, id, action) {
  button.disabled = true;
  message(id, 'Working…');
  try { await action(); }
  catch (error) { message(id, error instanceof Error ? error.message : 'Operation failed.', true); }
  finally { button.disabled = false; }
}

document.querySelectorAll('.tab').forEach(button => button.addEventListener('click', () => {
  document.querySelectorAll('.tab').forEach(tab => {
    const active = tab === button;
    tab.classList.toggle('active', active);
    tab.setAttribute('aria-selected', String(active));
    el(tab.dataset.tab).hidden = !active;
  });
}));

el('generate').addEventListener('click', event => run(event.currentTarget, 'receiver-message', async () => {
  if (recipient && !window.confirm('Replace the current key? Download its encrypted backup first. Existing packages need the old key.')) {
    message('receiver-message', 'Current key kept.');
    return;
  }
  recipient = makeRecipient();
  await showRecipient();
  el('decrypted-download').hidden = true;
  message('receiver-message', 'Key pair generated in this browser. Download an encrypted backup before closing the tab.');
}));

el('copy-public').addEventListener('click', event => run(event.currentTarget, 'receiver-message', async () => {
  await navigator.clipboard.writeText(el('public-key').value);
  message('receiver-message', 'Public key copied. Share its fingerprint separately.');
}));

el('download-key').addEventListener('click', event => run(event.currentTarget, 'receiver-message', async () => {
  if (!recipient) throw new Error('Generate or restore a key first.');
  const backup = await makeBackup(recipient, el('backup-password').value);
  const url = URL.createObjectURL(new Blob([backup], { type: 'application/json' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = 'qshield-private-backup.json';
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 60000);
  el('backup-password').value = '';
  message('receiver-message', 'Encrypted backup downloaded. Keep the file and password private.');
}));

el('restore-key').addEventListener('click', event => run(event.currentTarget, 'receiver-message', async () => {
  const file = el('key-file').files[0];
  if (!file) throw new Error('Choose your browser key backup file first.');
  if (file.size > 8192) throw new Error('The backup file is too large.');
  const restored = await restoreBackup(await file.text(), el('restore-password').value);
  recipient = restored;
  await showRecipient();
  el('restore-password').value = '';
  message('receiver-message', 'Private key restored in this browser.');
}));

el('check-public').addEventListener('click', event => run(event.currentTarget, 'encrypt-message', async () => {
  el('recipient-fingerprint').textContent = await publicFingerprint(el('recipient-key').value);
  el('recipient-fingerprint').hidden = false;
  message('encrypt-message', 'Compare this fingerprint with the receiver over another channel.');
}));

el('encrypt').addEventListener('click', event => run(event.currentTarget, 'encrypt-message', async () => {
  el('encrypted-download').hidden = true;
  const file = el('source-file').files[0];
  if (!file) throw new Error('Choose a file first.');
  if (file.size > MAX_FILE_SIZE) throw new Error('Choose a file no larger than 25 MB.');
  const fingerprint = await publicFingerprint(el('recipient-key').value);
  if (el('recipient-fingerprint').hidden || el('recipient-fingerprint').textContent !== fingerprint) {
    el('recipient-fingerprint').textContent = fingerprint;
    el('recipient-fingerprint').hidden = false;
    throw new Error('Compare the displayed fingerprint with the receiver, then click Encrypt file again.');
  }
  const encrypted = await encryptPackage(new Uint8Array(await file.arrayBuffer()), file.name, el('recipient-key').value);
  download('encrypted-download', '↓ Download encrypted package', encrypted, `${file.name}.qshield`, 'application/octet-stream');
  message('encrypt-message', 'Encrypted package ready. Share the downloaded file with the receiver.');
}));

el('decrypt').addEventListener('click', event => run(event.currentTarget, 'decrypt-message', async () => {
  el('decrypted-download').hidden = true;
  if (!recipient) throw new Error('Generate or restore the receiver key first.');
  const file = el('package-file').files[0];
  if (!file) throw new Error('Choose a .qshield package first.');
  if (file.size > MAX_FILE_SIZE + 100000) throw new Error('The package is too large for this browser demo.');
  const result = await decryptPackage(await file.arrayBuffer(), recipient);
  download('decrypted-download', '↓ Download verified file', result.bytes, result.filename, 'application/octet-stream');
  message('decrypt-message', 'Package integrity verified. File decrypted in your browser.');
}));
