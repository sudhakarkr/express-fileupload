const assert = require('assert');
const fileFactory = require('../lib/fileFactory');

// 1. Test directory traversal sanitization on uploaded filename
const traversalName = '../../etc/passwd';
const file = fileFactory({
  name: traversalName,
  buffer: Buffer.from('malicious content')
});

// The patched safeFilename should strip directory traversal elements
assert.strictEqual(file.name, 'passwd', 'Uploaded filename should be sanitized to its safe basename');

// 2. Test directory traversal prevention in mv() destination path
const fileToMove = fileFactory({
  name: 'test.txt',
  buffer: Buffer.from('data')
});

// It should return or reject with an error when directory traversal sequences are used in mv()
fileToMove.mv('../unsafe-destination/test.txt', (err) => {
  assert.ok(err instanceof Error, 'Expected mv() destination path validation to fail with an Error');
  assert.match(err.message, /directory traversal/, 'Error message should complain about directory traversal');
  
  // Also test with Promise API
  fileToMove.mv('../unsafe-destination/test.txt')
    .then(() => {
      assert.fail('Expected mv() promise to reject for unsafe path');
    })
    .catch((promiseErr) => {
      assert.ok(promiseErr instanceof Error);
      assert.match(promiseErr.message, /directory traversal/);
      console.log('REGRESSION: Verified that directory traversal is prevented in filenames and mv() paths.');
    });
});
