#!/usr/bin/env node
/**
 * Reference capture program: path API family.
 * Run against Node.js or Bun to generate fixture JSON.
 *
 * Usage: node scripts/captures/capture_path.js [api_name]
 * Output: JSON fixture array to stdout
 */

const path = require('path');

const ORACLE_SOURCE = `node-${process.version.slice(1)}`;

function makeFixture(apiName, scenario, band, input, expectedOutput, tags) {
  return {
    id: `fixture:path:${apiName}:${scenario}`,
    api_family: 'path',
    api_name: apiName,
    band: band || 'core',
    description: `${apiName} — ${scenario}`,
    input,
    expected_output: expectedOutput,
    oracle_source: ORACLE_SOURCE,
    tags: ['path', apiName, ...(tags || [])],
  };
}

function captureJoin() {
  return [
    makeFixture('join', 'basic-segments', 'core',
      { args: ['foo', 'bar', 'baz'] },
      { return_value: path.join('foo', 'bar', 'baz'), error: null, side_effects: null },
      ['basic']),
    makeFixture('join', 'with-separator', 'core',
      { args: ['foo/', '/bar'] },
      { return_value: path.join('foo/', '/bar'), error: null, side_effects: null },
      ['normalize']),
    makeFixture('join', 'empty-segments', 'core',
      { args: ['foo', '', 'bar'] },
      { return_value: path.join('foo', '', 'bar'), error: null, side_effects: null },
      ['empty']),
    makeFixture('join', 'dot-segments', 'core',
      { args: ['foo', '.', 'bar'] },
      { return_value: path.join('foo', '.', 'bar'), error: null, side_effects: null },
      ['dot']),
    makeFixture('join', 'dotdot-segments', 'core',
      { args: ['foo', 'bar', '..', 'baz'] },
      { return_value: path.join('foo', 'bar', '..', 'baz'), error: null, side_effects: null },
      ['dotdot']),
  ];
}

function captureResolve() {
  return [
    makeFixture('resolve', 'relative-paths', 'core',
      { args: ['foo', 'bar'] },
      { return_value: '<ABS_PATH>/foo/bar', error: null, side_effects: null },
      ['relative']),
    makeFixture('resolve', 'absolute-override', 'core',
      { args: ['/foo', '/bar'] },
      { return_value: '/bar', error: null, side_effects: null },
      ['absolute']),
  ];
}

function captureParse() {
  const result = path.parse('/home/user/file.txt');
  return [
    makeFixture('parse', 'absolute-path', 'core',
      { args: ['/home/user/file.txt'] },
      { return_value: result, error: null, side_effects: null },
      ['parse']),
    makeFixture('parse', 'filename-only', 'core',
      { args: ['file.txt'] },
      { return_value: path.parse('file.txt'), error: null, side_effects: null },
      ['filename']),
  ];
}

function captureDirname() {
  return [
    makeFixture('dirname', 'basic', 'core',
      { args: ['/foo/bar/baz.txt'] },
      { return_value: path.dirname('/foo/bar/baz.txt'), error: null, side_effects: null },
      ['basic']),
    makeFixture('dirname', 'root-path', 'core',
      { args: ['/'] },
      { return_value: path.dirname('/'), error: null, side_effects: null },
      ['root']),
  ];
}

function captureBasename() {
  return [
    makeFixture('basename', 'with-extension', 'core',
      { args: ['/foo/bar/baz.txt'] },
      { return_value: path.basename('/foo/bar/baz.txt'), error: null, side_effects: null },
      ['basic']),
    makeFixture('basename', 'strip-extension', 'core',
      { args: ['/foo/bar/baz.txt', '.txt'] },
      { return_value: path.basename('/foo/bar/baz.txt', '.txt'), error: null, side_effects: null },
      ['strip-ext']),
  ];
}

function captureExtname() {
  return [
    makeFixture('extname', 'simple', 'core',
      { args: ['file.txt'] },
      { return_value: path.extname('file.txt'), error: null, side_effects: null },
      ['basic']),
    makeFixture('extname', 'no-extension', 'core',
      { args: ['Makefile'] },
      { return_value: path.extname('Makefile'), error: null, side_effects: null },
      ['none']),
    makeFixture('extname', 'dotfile', 'core',
      { args: ['.gitignore'] },
      { return_value: path.extname('.gitignore'), error: null, side_effects: null },
      ['dotfile']),
  ];
}

// Dispatch
const api = process.argv[2];
const captureMap = {
  join: captureJoin, resolve: captureResolve, parse: captureParse,
  dirname: captureDirname, basename: captureBasename, extname: captureExtname,
};

if (api && captureMap[api]) {
  console.log(JSON.stringify(captureMap[api](), null, 2));
} else {
  const all = Object.values(captureMap).flatMap(fn => fn());
  console.log(JSON.stringify(all, null, 2));
}
