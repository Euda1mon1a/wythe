const { execFileSync } = require('node:child_process');
const { mkdtempSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join, resolve } = require('node:path');

const output = mkdtempSync(join(tmpdir(), 'wythe-scene-tests-'));
try {
  execFileSync(process.execPath, [resolve('node_modules/typescript/bin/tsc'), '-p', 'tsconfig.scene-tests.json', '--outDir', output], { stdio: 'inherit' });
  execFileSync(process.execPath, ['--test', join(output, 'tests/scene.test.js')], {
    stdio: 'inherit', env: { ...process.env, NODE_PATH: resolve('node_modules') },
  });
} finally {
  rmSync(output, { recursive: true, force: true });
}
