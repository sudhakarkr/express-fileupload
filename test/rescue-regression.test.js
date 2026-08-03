'use strict';

// Regression test for express-fileupload path traversal via crafted
// Content-Disposition filename and prototype pollution via nested field keys.
// This test is self-contained (no test framework) and imports the library
// by relative path per package.json main entry.

const assert = require('node:assert');
const path = require('path');

const utilities = require('../lib/utilities.js');
const { parseFileName, buildFields, isSafeFromPollution, sanitizeFileName } = utilities;

// --- Test 1: Path traversal via filename ---
// An attacker sends a filename like "../../../../etc/passwd". The patched
// parseFileName MUST strip path components so the result cannot escape the
// upload directory when joined with a destination path.
const maliciousNames = [
  '../../../../etc/passwd',
  '..\\..\\..\\windows\\system32\\evil.exe',
  '/etc/passwd',
  'foo/../../bar.txt',
  'subdir/inner.txt'
];

for (const name of maliciousNames) {
  const parsed = parseFileName({}, name);
  assert.strictEqual(typeof parsed, 'string', `parseFileName should return a string for ${name}`);
  assert.ok(parsed.length > 0, `parseFileName returned empty for ${name}`);
  // Must not contain path separators.
  assert.ok(!parsed.includes('/'), `parseFileName leaked '/' for input ${JSON.stringify(name)} => ${parsed}`);
  assert.ok(!parsed.includes('\\'), `parseFileName leaked '\\' for input ${JSON.stringify(name)} => ${parsed}`);
  // Must not be a traversal token.
  assert.notStrictEqual(parsed, '..', `parseFileName produced '..' for ${name}`);
  assert.notStrictEqual(parsed, '.', `parseFileName produced '.' for ${name}`);
  // Joining with a destination directory must stay within it.
  const dest = '/uploads';
  const joined = path.posix.normalize(path.posix.join(dest, parsed.replace(/\\/g, '/')));
  assert.ok(joined.startsWith(dest + '/') || joined === dest,
    `Joined path escapes upload dir: ${joined} (from ${name})`);
}

// sanitizeFileName should be exported and strip traversal too.
assert.strictEqual(typeof sanitizeFileName, 'function', 'sanitizeFileName must be exported');
assert.strictEqual(sanitizeFileName('../../etc/passwd'), 'passwd');
assert.strictEqual(sanitizeFileName('..'), '');
assert.strictEqual(sanitizeFileName('/'), '');

// --- Test 2: Prototype pollution via buildFields ---
// buildFields must reject keys like __proto__, constructor, prototype.
assert.strictEqual(typeof isSafeFromPollution, 'function', 'isSafeFromPollution must be exported');
assert.strictEqual(isSafeFromPollution({}, '__proto__'), false);
assert.strictEqual(isSafeFromPollution({}, 'constructor'), false);
assert.strictEqual(isSafeFromPollution({}, 'prototype'), false);

const before = ({}).polluted;
assert.strictEqual(before, undefined, 'precondition: Object.prototype.polluted must be undefined');

let obj = Object.create(null);
obj = buildFields(obj, '__proto__', { polluted: 'yes' });

// After the call, Object.prototype must NOT have been polluted.
assert.strictEqual(({}).polluted, undefined,
  'Prototype pollution occurred: Object.prototype.polluted was set via buildFields');

// Also verify the malicious key was not stored on the target object either.
assert.strictEqual(obj.polluted, undefined,
  'buildFields incorrectly assigned the polluting payload');

console.log('REGRESSION: verified parseFileName strips path traversal (../../etc/passwd -> basename) and buildFields/isSafeFromPollution block __proto__/constructor/prototype keys to prevent prototype pollution.');
