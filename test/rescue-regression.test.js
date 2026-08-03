'use strict';

// Regression test for path-traversal sanitization in express-fileupload's
// parseFileName. On the vulnerable code, a filename containing directory
// traversal sequences (e.g. "../../etc/passwd") is returned as-is and would
// be joined into the upload destination, enabling arbitrary file write.
// The patched code sanitizes the filename to strip any directory components.

const assert = require('node:assert');
const path = require('path');

const utilities = require('../lib/utilities.js');
const { parseFileName } = utilities;

assert.strictEqual(typeof parseFileName, 'function',
  'parseFileName must be exported from lib/utilities.js');

const maliciousInputs = [
  '../../etc/passwd',
  '..\\..\\windows\\system32\\cmd.exe',
  '/etc/passwd',
  'foo/../../bar.txt',
  'subdir/evil.sh'
];

for (const evil of maliciousInputs) {
  const parsed = parseFileName({}, evil);

  assert.strictEqual(typeof parsed, 'string',
    `parseFileName should return a string for input ${JSON.stringify(evil)}`);

  // The sanitized filename must not contain any path separators.
  assert.ok(parsed.indexOf('/') === -1,
    `parseFileName leaked '/' for input ${JSON.stringify(evil)} -> ${JSON.stringify(parsed)}`);
  assert.ok(parsed.indexOf('\\') === -1,
    `parseFileName leaked '\\' for input ${JSON.stringify(evil)} -> ${JSON.stringify(parsed)}`);

  // It must not equal traversal identifiers.
  assert.notStrictEqual(parsed, '..',
    `parseFileName returned traversal identifier for ${JSON.stringify(evil)}`);
  assert.notStrictEqual(parsed, '.',
    `parseFileName returned dot identifier for ${JSON.stringify(evil)}`);

  // Joining the sanitized name with an intended upload directory must not
  // escape that directory. This is the core property that prevents arbitrary
  // file write via crafted Content-Disposition filenames.
  const uploadDir = path.resolve('/tmp/uploads');
  const resolved = path.resolve(uploadDir, parsed);
  assert.ok(
    resolved === uploadDir || resolved.startsWith(uploadDir + path.sep),
    `sanitized filename escaped upload dir for ${JSON.stringify(evil)}: ` +
      `resolved=${resolved}, uploadDir=${uploadDir}, parsed=${parsed}`
  );

  // Specifically, it must never resolve to the system /etc/passwd or to a
  // Windows system location.
  assert.notStrictEqual(resolved, path.resolve('/etc/passwd'),
    `parseFileName allowed traversal to /etc/passwd for ${JSON.stringify(evil)}`);
}

// Also verify that the fileFactory sink rejects clearly invalid destinations
// (defense in depth). This is optional but strengthens the regression net.
try {
  const fileFactory = require('../lib/fileFactory.js');
  const file = fileFactory({
    buffer: Buffer.from('hello'),
    name: 'safe.txt',
    tempFilePath: undefined,
    hash: '',
    size: 5,
    encoding: '7bit',
    truncated: false,
    mimetype: 'text/plain'
  }, { useTempFiles: false });

  assert.strictEqual(typeof file.mv, 'function', 'file.mv must be a function');

  // NUL byte in destination path must be rejected.
  let cbErr = null;
  file.mv('/tmp/uploads/foo\0.txt', (err) => { cbErr = err; });
  assert.ok(cbErr instanceof Error,
    'mv() must reject destination paths containing NUL bytes');
} catch (e) {
  // If fileFactory cannot be loaded standalone for some reason, rethrow so
  // the regression is visible.
  throw e;
}

console.log('REGRESSION: parseFileName strips path traversal components ' +
  '(e.g. "../../etc/passwd") so sanitized filenames cannot escape the upload directory.');
