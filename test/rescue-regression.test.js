'use strict';

const assert = require('assert');
const fileFactory = require('../lib/fileFactory');

// Create a dummy file object using fileFactory
const file = fileFactory({
  name: '../../malicious.txt',
  buffer: Buffer.from('test'),
  size: 4,
  encoding: 'utf8',
  tempFilePath: '',
  truncated: false,
  mimetype: 'text/plain'
}, {});

// 1. Verify filename sanitization
assert.strictEqual(file.name, 'malicious.txt', 'Filename should be sanitized to its basename to prevent path traversal');

// 2. Verify mv() rejects path traversal destinations
file.mv('../unsafe-destination.txt')
  .then(() => {
    assert.fail('mv() should have rejected a destination path containing directory traversal.');
  })
  .catch((err) => {
    if (err.name === 'AssertionError') {
      throw err;
    }
    assert.ok(err instanceof Error, 'Expected an Error object');
    assert.match(err.message, /directory traversal/, 'Expected error to indicate a directory traversal issue');
    console.log('REGRESSION: Successfully prevented directory traversal and sanitized filename.');
    process.exit(0);
  });
