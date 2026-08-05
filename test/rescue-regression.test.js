const assert = require('assert');
const fileFactory = require('../lib/fileFactory');

async function run() {
  // 1. Sanitize filename check
  const file1 = fileFactory({ name: '../../dangerous.txt', buffer: Buffer.from('test') });
  assert.strictEqual(file1.name, 'dangerous.txt', 'Should sanitize directory traversal from filename');

  const file2 = fileFactory({ name: 'dangerous\\..\\..\\file.txt', buffer: Buffer.from('test') });
  assert.strictEqual(file2.name, 'file.txt', 'Should sanitize backslash directory traversal from filename');

  // 2. mv() path check
  const file3 = fileFactory({ name: 'safe.txt', buffer: Buffer.from('test') });
  
  let rejected = false;
  try {
    await file3.mv('../dangerous/path.txt');
  } catch (err) {
    if (err && err.message && err.message.includes('directory traversal')) {
      rejected = true;
    }
  }
  
  assert.strictEqual(rejected, true, 'mv() should reject paths with directory traversal sequences');

  console.log('REGRESSION: Verified that directory traversal is prevented in filenames and mv() paths.');
}

run().catch(err => {
  console.error(err);
  process.exit(1);
});
