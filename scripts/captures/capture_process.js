#!/usr/bin/env node
/**
 * Reference capture program: process API family.
 * Run against Node.js or Bun to generate fixture JSON.
 *
 * Usage: node scripts/captures/capture_process.js [api_name]
 * Output: JSON fixture array to stdout
 */

const ORACLE_SOURCE = `node-${process.version.slice(1)}`;

function makeFixture(apiName, scenario, band, input, expectedOutput, tags) {
  return {
    id: `fixture:process:${apiName}:${scenario}`,
    api_family: 'process',
    api_name: apiName,
    band: band || 'core',
    description: `${apiName} — ${scenario}`,
    input,
    expected_output: expectedOutput,
    oracle_source: ORACLE_SOURCE,
    tags: ['process', apiName, ...(tags || [])],
  };
}

function captureEnv() {
  return [
    makeFixture('env', 'read-existing', 'core',
      { args: [], env: { TEST_VAR: 'hello' } },
      { return_value: 'hello', error: null, side_effects: null },
      ['read']),
    makeFixture('env', 'read-undefined', 'core',
      { args: [], env: {} },
      { return_value: undefined, error: null, side_effects: null },
      ['undefined']),
    makeFixture('env', 'set-and-read', 'core',
      { args: [], env: {} },
      { return_value: 'new_value', error: null, side_effects: [{ type: 'env_set', key: 'NEW_VAR', value: 'new_value' }] },
      ['set']),
  ];
}

function captureArgv() {
  return [
    makeFixture('argv', 'basic-args', 'core',
      { args: ['--flag', 'value'] },
      { return_value: ['<RUNTIME>', '<SCRIPT>', '--flag', 'value'], error: null, side_effects: null },
      ['basic']),
    makeFixture('argv', 'no-args', 'core',
      { args: [] },
      { return_value: ['<RUNTIME>', '<SCRIPT>'], error: null, side_effects: null },
      ['empty']),
  ];
}

function captureCwd() {
  return [
    makeFixture('cwd', 'returns-string', 'core',
      { args: [] },
      { return_value: '<CWD>', error: null, side_effects: null },
      ['basic']),
  ];
}

function capturePid() {
  return [
    makeFixture('pid', 'is-number', 'core',
      { args: [] },
      { return_value: '<PID>', error: null, side_effects: null },
      ['basic']),
  ];
}

function captureVersion() {
  return [
    makeFixture('version', 'format', 'core',
      { args: [] },
      { return_value: '<VERSION>', error: null, side_effects: null },
      ['format']),
  ];
}

// Dispatch
const api = process.argv[2];
const captureMap = {
  env: captureEnv, argv: captureArgv, cwd: captureCwd,
  pid: capturePid, version: captureVersion,
};

if (api && captureMap[api]) {
  console.log(JSON.stringify(captureMap[api](), null, 2));
} else {
  const all = Object.values(captureMap).flatMap(fn => fn());
  console.log(JSON.stringify(all, null, 2));
}
