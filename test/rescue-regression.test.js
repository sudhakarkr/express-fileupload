'use strict';

// Regression test for path traversal via uploaded file names.
// The fix sanitizes file names in parseFileName so path separators and
// traversal sequences are stripped before the name is used to build a
// destination path.

const assert = require('node:assert');
const path = require('path');
const { parseFileName } = require('../lib/utilities');

function check(input, opts) {
  const result = parseFileName(opts || {}, input);
  // Result must be a bare basename with no directory components.
  assert.strictEqual(
    typeof result,
    'string',
    `parseFileName should return a string, got ${typeof result}`
  );
  assert.ok(result.length > 0, `parseFileName returned empty string for input ${JSON.stringify(input)}`);
  assert.ok(
    !result.includes('/'),
    `parseFileName result must not contain '/'. Got: ${JSON.stringify(result)} for input ${JSON.stringify(input)}`
  );
  assert.ok(
    !result.includes('\\'),
    `parseFileName result must not contain '\\'. Got: ${JSON.stringify(result)} for input ${JSON.stringify(input)}`
  );
  assert.notStrictEqual(result, '..', `parseFileName must not return '..' for input ${JSON.stringify(input)}`);
  assert.notStrictEqual(result, '.', `parseFileName must not return '.' for input ${JSON.stringify(input)}`);
  // path.basename(result) should equal result — i.e. it's already a basename.
  assert.strictEqual(
    path.basename(result),
    result,
    `parseFileName result must equal its basename. Got: ${JSON.stringify(result)}`
  );
  // Simulate joining with an upload dir: the joined path must stay inside uploadDir.
  const uploadDir = '/tmp/uploads';
  const joined = path.resolve(uploadDir, result);
  assert.ok(
    joined.startsWith(path.resolve(uploadDir) + path.sep) || joined === path.resolve(uploadDir, result),
    `Resolved upload path escapes uploadDir. Got: ${joined}`
  );
  assert.ok(
    path.dirname(joined) === path.resolve(uploadDir),
    `Uploaded file must land directly in uploadDir. dirname=${path.dirname(joined)} expected=${path.resolve(uploadDir)}`
  );
  return result;
}

// Classic traversal attempts
check('../../../etc/passwd');
check('..\\..\\..\\windows\\system32\\evil.dll');
check('/etc/passwd');
check('foo/bar/baz.txt');
check('subdir/evil.sh');
check('..');
check('.');

// Also verify with safeFileNames + uriDecodeFileNames options (attacker
// may URL-encode separators to try to bypass naive checks).
check('%2e%2e%2f%2e%2e%2fetc%2fpasswd', { uriDecodeFileNames: true });
check('..%2F..%2Fetc%2Fpasswd', { uriDecodeFileNames: true });

console.log('REGRESSION: parseFileName strips path separators and traversal sequences from uploaded file names (CVE path-traversal via filename).');
