'use strict';

// Regression test for CVE-2022-27261 / express-fileupload arbitrary file overwrite.
// This test targets lib/fileFactory.js directly to verify:
//   1. Uploaded filenames are sanitized (path components stripped).
//   2. mv() rejects destination paths containing directory traversal sequences
//      or NUL bytes rather than passing them to the filesystem sink.
//
// On the vulnerable code (installed_version 0.0.5), the file's `name` still
// contains the traversal payload and mv() will happily accept a traversal
// destination, so these assertions fail.

const assert = require('node:assert');
const path = require('path');
const fs = require('fs');
const os = require('os');

const fileFactory = require('../lib/fileFactory');

let failures = 0;
function check(name, fn) {
  try {
    fn();
  } catch (e) {
    failures++;
    console.error(`FAIL: ${name}: ${e && e.message}`);
  }
}

// ---------------------------------------------------------------------------
// 1. Filename sanitization at parse time.
// ---------------------------------------------------------------------------
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'efu-regression-'));
const buffer = Buffer.from('malicious payload');

const traversalName = '../../../../../../etc/passwd';
const fileObj = fileFactory({
  name: traversalName,
  buffer: buffer,
  size: buffer.length,
  encoding: '7bit',
  tempFilePath: '',
  truncated: false,
  mimetype: 'text/plain',
  hash: 'deadbeef'
}, { useTempFiles: false });

check('filename is sanitized (no path separators)', () => {
  assert.strictEqual(typeof fileObj.name, 'string');
  assert.ok(!fileObj.name.includes('/'), `name still contains '/': ${fileObj.name}`);
  assert.ok(!fileObj.name.includes('\\'), `name still contains '\\': ${fileObj.name}`);
  assert.notStrictEqual(fileObj.name, traversalName);
  // basename of the traversal payload would be "passwd"; that's acceptable.
  assert.strictEqual(fileObj.name, 'passwd');
});

// Filename containing NUL byte should be rejected (empty string).
const nulFile = fileFactory({
  name: 'safe.txt\0.png',
  buffer: buffer,
  size: buffer.length,
  encoding: '7bit',
  tempFilePath: '',
  truncated: false,
  mimetype: 'text/plain',
  hash: ''
}, { useTempFiles: false });

check('filename with NUL byte is rejected', () => {
  assert.ok(!nulFile.name.includes('\0'), 'NUL byte survived in name');
  assert.strictEqual(nulFile.name, '');
});

// ---------------------------------------------------------------------------
// 2. mv() destination validation.
// ---------------------------------------------------------------------------
// A destination path containing '..' components must be rejected without
// touching the filesystem.
const maliciousDest = path.join(tmpDir, '..', '..', 'pwned.txt');

(async () => {
  let rejected = false;
  let rejectionErr = null;
  try {
    await fileObj.mv(maliciousDest);
  } catch (e) {
    rejected = true;
    rejectionErr = e;
  }

  check('mv() rejects traversal destination path (promise API)', () => {
    assert.ok(rejected, 'mv() resolved instead of rejecting traversal destination');
    assert.ok(rejectionErr instanceof Error, 'rejection value is not an Error');
    assert.ok(!fs.existsSync(maliciousDest),
      `traversal destination was written to disk: ${maliciousDest}`);
  });

  // Callback API: should invoke callback with an Error, not perform the move.
  await new Promise((resolve) => {
    fileObj.mv(maliciousDest, (err) => {
      check('mv() rejects traversal destination path (callback API)', () => {
        assert.ok(err instanceof Error, 'callback did not receive an Error');
        assert.ok(!fs.existsSync(maliciousDest),
          'traversal destination created via callback API');
      });
      resolve();
    });
  });

  // NUL byte in destination path must also be rejected.
  let nulRejected = false;
  try {
    await fileObj.mv(path.join(tmpDir, 'ok.txt\0.bin'));
  } catch (e) {
    nulRejected = true;
  }
  check('mv() rejects NUL byte in destination', () => {
    assert.ok(nulRejected, 'mv() accepted destination containing NUL byte');
  });

  // Cleanup best-effort.
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_) {}

  console.log('REGRESSION: CVE-2022-27261 — express-fileupload sanitizes traversal filenames and rejects traversal/NUL destinations in mv().');

  if (failures > 0) {
    console.error(`${failures} regression check(s) failed`);
    process.exit(1);
  }
})().catch((e) => {
  console.error('Unexpected error in regression test:', e);
  process.exit(1);
});
