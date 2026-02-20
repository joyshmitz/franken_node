#!/usr/bin/env node
/**
 * Reference capture program: fs API family.
 * Run against Node.js or Bun to generate fixture JSON.
 *
 * Usage: node scripts/captures/capture_fs.js [api_name]
 * Output: JSON fixture array to stdout
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

const ORACLE_SOURCE = `node-${process.version.slice(1)}`;

function makeFixture(apiName, scenario, band, input, expectedOutput, tags) {
  return {
    id: `fixture:fs:${apiName}:${scenario}`,
    api_family: 'fs',
    api_name: apiName,
    band: band || 'core',
    description: `${apiName} — ${scenario}`,
    input,
    expected_output: expectedOutput,
    oracle_source: ORACLE_SOURCE,
    tags: ['fs', apiName, ...(tags || [])],
  };
}

function captureReadFile() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'capture-'));
  const fixtures = [];

  try {
    // utf8-basic
    const f1 = path.join(tmpDir, 'hello.txt');
    fs.writeFileSync(f1, 'hello world\n');
    fixtures.push(makeFixture('readFile', 'utf8-basic', 'core',
      { args: ['hello.txt', { encoding: 'utf8' }], files: { 'hello.txt': 'hello world\n' } },
      { return_value: fs.readFileSync(f1, 'utf8'), error: null, side_effects: null },
      ['utf8']));

    // buffer-no-encoding
    fixtures.push(makeFixture('readFile', 'buffer-no-encoding', 'core',
      { args: ['hello.txt'], files: { 'hello.txt': 'hello world\n' } },
      { return_value: '<Buffer>', error: null, side_effects: null },
      ['buffer']));

    // nonexistent-file
    let errCode = null;
    try { fs.readFileSync(path.join(tmpDir, 'missing.txt')); } catch (e) { errCode = e.code; }
    fixtures.push(makeFixture('readFile', 'nonexistent-enoent', 'core',
      { args: ['missing.txt', { encoding: 'utf8' }], files: {} },
      { return_value: null, error: { code: errCode }, side_effects: null },
      ['error']));

    // empty-file
    const f2 = path.join(tmpDir, 'empty.txt');
    fs.writeFileSync(f2, '');
    fixtures.push(makeFixture('readFile', 'empty-file', 'core',
      { args: ['empty.txt', { encoding: 'utf8' }], files: { 'empty.txt': '' } },
      { return_value: fs.readFileSync(f2, 'utf8'), error: null, side_effects: null },
      ['edge']));

  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
  return fixtures;
}

function captureWriteFile() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'capture-'));
  const fixtures = [];

  try {
    // basic-write
    const f1 = path.join(tmpDir, 'out.txt');
    fs.writeFileSync(f1, 'test data\n');
    fixtures.push(makeFixture('writeFile', 'basic-write', 'core',
      { args: ['out.txt', 'test data\n'] },
      { return_value: null, error: null, side_effects: [{ type: 'file_created', path: 'out.txt', content: 'test data\n' }] },
      ['basic']));

    // overwrite-existing
    fs.writeFileSync(f1, 'original');
    fs.writeFileSync(f1, 'replaced');
    fixtures.push(makeFixture('writeFile', 'overwrite-existing', 'core',
      { args: ['out.txt', 'replaced'], files: { 'out.txt': 'original' } },
      { return_value: null, error: null, side_effects: [{ type: 'file_modified', path: 'out.txt', content: 'replaced' }] },
      ['overwrite']));

    // write-with-encoding
    fs.writeFileSync(path.join(tmpDir, 'enc.txt'), 'café', 'utf8');
    fixtures.push(makeFixture('writeFile', 'utf8-encoding', 'core',
      { args: ['enc.txt', 'café', { encoding: 'utf8' }] },
      { return_value: null, error: null, side_effects: [{ type: 'file_created', path: 'enc.txt', content: 'café' }] },
      ['encoding', 'utf8']));

  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
  return fixtures;
}

// Dispatch
const api = process.argv[2];
const captureMap = { readFile: captureReadFile, writeFile: captureWriteFile };

if (api && captureMap[api]) {
  console.log(JSON.stringify(captureMap[api](), null, 2));
} else {
  const all = Object.values(captureMap).flatMap(fn => fn());
  console.log(JSON.stringify(all, null, 2));
}
