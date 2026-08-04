// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import {describe, test} from 'node:test';
import {fileURLToPath} from 'node:url';
import {promisify} from 'node:util';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const esbuild = require('esbuild');

const sourcePath = fileURLToPath(new URL('../DarwinProcessScanner.ts', import.meta.url));
const transformedSource = esbuild.transformSync(readFileSync(sourcePath, 'utf8'), {
	loader: 'ts',
	format: 'cjs',
	platform: 'node',
	target: 'node20',
}).code;

function makeExecError(message, code) {
	const error = new Error(message);
	error.code = code;
	return error;
}

function plain(value) {
	return JSON.parse(JSON.stringify(value));
}

function loadDarwinProcessScanner({execFile, candidateApps = [], matchExecutable = () => false}) {
	const calls = [];
	const matcherCalls = [];
	const execFileStub = (file, args, options, callback) => {
		calls.push({file, args, options});
		execFile(file, args, options, callback);
	};
	execFileStub[promisify.custom] = (file, args, options) =>
		new Promise((resolve, reject) => {
			execFileStub(file, args, options, (error, stdout, stderr) => {
				if (error) {
					error.stdout = stdout;
					error.stderr = stderr;
					reject(error);
					return;
				}
				resolve({stdout, stderr});
			});
		});
	const module = {exports: {}};
	const context = vm.createContext({
		module,
		exports: module.exports,
		console,
		Buffer,
		process: {platform: 'darwin'},
		require: (specifier) => {
			if (specifier === 'node:child_process') return {execFile: execFileStub};
			if (specifier === 'electron-log') return {info() {}, warn() {}, error() {}};
			if (specifier === '@electron/main/DetectableApplications') {
				return {
					matchLinuxExecutable: (executable, variations, args, platform) => {
						matcherCalls.push({executable, variations: [...variations], args, platform});
						return matchExecutable(executable, variations, args, platform);
					},
				};
			}
			if (specifier === '@electron/main/rpc/RpcConstants') {
				return {PROCESS_QUERY_MAX_BUFFER_BYTES: 4 * 1024 * 1024, PROCESS_QUERY_TIMEOUT: 10000};
			}
			if (specifier === '@electron/main/rpc/ProcessScanState') {
				return {
					isIgnoredPath: (value) => value.toLowerCase().includes('easyanticheat'),
					generatePathVariations: (normalizedPath) => {
						const segments = normalizedPath.split('/');
						const variations = [];
						for (let i = 1; i <= segments.length; i++) {
							variations.push(segments.slice(-i).join('/'));
						}
						return variations;
					},
					getCandidateApps: () => candidateApps,
				};
			}
			return require(specifier);
		},
	});
	vm.runInContext(transformedSource, context, {filename: sourcePath});
	return {...module.exports, calls, matcherCalls};
}

function respondByFormat(byFormat) {
	return (_file, args, _options, callback) => {
		const format = args[1];
		const stdout = byFormat[format];
		if (stdout === undefined) {
			callback(makeExecError(`unexpected format ${format}`, 1), '', '');
			return;
		}
		callback(null, stdout, '');
	};
}

describe('DarwinProcessScanner', () => {
	test('keeps spaces in executable paths when parsing a ps column', () => {
		const scanner = loadDarwinProcessScanner({execFile: respondByFormat({})});

		const values = scanner.parsePsColumn(
			[
				'  456 /Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
				'  789 /bin/bash',
				'',
				'garbage line without a pid',
			].join('\n'),
		);

		assert.equal(values.get(456), '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome');
		assert.equal(values.get(789), '/bin/bash');
		assert.equal(values.size, 2);
	});

	test('extracts every app bundle segment from a path', () => {
		const scanner = loadDarwinProcessScanner({execFile: respondByFormat({})});

		assert.deepEqual(plain(scanner.appBundleVariations('/applications/osu!.app/contents/macos/osu!')), ['osu!.app']);
		assert.deepEqual(
			plain(
				scanner.appBundleVariations(
					'/applications/discord.app/contents/frameworks/discord helper.app/contents/macos/discord helper',
				),
			),
			['discord.app', 'discord helper.app'],
		);
		assert.deepEqual(plain(scanner.appBundleVariations('/usr/bin/ssh')), []);
	});

	test('joins the comm and args queries on pid', async () => {
		const scanner = loadDarwinProcessScanner({
			execFile: respondByFormat({
				'pid=,comm=': '  10 /Applications/osu!.app/Contents/MacOS/osu!\n',
				'pid=,args=': '  10 /Applications/osu!.app/Contents/MacOS/osu! --tournament\n',
			}),
		});

		const processes = await scanner.enumerateDarwinProcesses();

		assert.deepEqual(plain(processes), [
			{
				pid: 10,
				path: '/Applications/osu!.app/Contents/MacOS/osu!',
				args: ['/Applications/osu!.app/Contents/MacOS/osu! --tournament'],
			},
		]);
		assert.deepEqual(
			scanner.calls.map((call) => plain(call.args)[1]),
			['pid=,comm=', 'pid=,args='],
		);
	});

	test('falls back to the executable path when a pid has no args row', async () => {
		const scanner = loadDarwinProcessScanner({
			execFile: respondByFormat({'pid=,comm=': '  11 /usr/bin/tool\n', 'pid=,args=': '\n'}),
		});

		const processes = await scanner.enumerateDarwinProcesses();

		assert.deepEqual(plain(processes), [{pid: 11, path: '/usr/bin/tool', args: ['/usr/bin/tool']}]);
	});

	test('drops anti-cheat processes', async () => {
		const scanner = loadDarwinProcessScanner({
			execFile: respondByFormat({
				'pid=,comm=': '  12 /Library/EasyAntiCheat/easyanticheat\n  13 /usr/bin/tool\n',
				'pid=,args=': '  12 /Library/EasyAntiCheat/easyanticheat\n  13 /usr/bin/tool\n',
			}),
		});

		const processes = await scanner.enumerateDarwinProcesses();

		assert.deepEqual(
			plain(processes).map((entry) => entry.pid),
			[13],
		);
	});

	test('returns empty when ps is unavailable', async () => {
		const scanner = loadDarwinProcessScanner({
			execFile: (_file, _args, _options, callback) => callback(makeExecError('spawn ENOENT', 'ENOENT'), '', ''),
		});

		assert.deepEqual(plain(await scanner.enumerateDarwinProcesses()), []);
	});

	test('offers the app bundle name to the executable matcher', () => {
		const scanner = loadDarwinProcessScanner({
			execFile: respondByFormat({}),
			candidateApps: [{id: 'osu', name: 'osu!', executables: [{name: 'osu!.app', os: 'darwin'}]}],
			matchExecutable: (executable, variations) => variations.includes(executable.name),
		});

		const app = scanner.matchDarwinProcess({
			pid: 10,
			path: '/Applications/osu!.app/Contents/MacOS/osu!',
			args: ['/Applications/osu!.app/Contents/MacOS/osu!'],
		});

		assert.equal(plain(app).name, 'osu!');
		const [matcherCall] = scanner.matcherCalls;
		assert.equal(matcherCall.platform, 'darwin');
		assert.ok(
			matcherCall.variations.includes('osu!.app'),
			'the bundle name must be offered, otherwise darwin .app rules never match',
		);
		assert.equal(matcherCall.variations[0], 'osu!', 'the basename must stay first for >-prefixed exact matches');
	});

	test('returns null when no candidate executable matches', () => {
		const scanner = loadDarwinProcessScanner({
			execFile: respondByFormat({}),
			candidateApps: [{id: 'osu', name: 'osu!', executables: [{name: 'osu!.app', os: 'darwin'}]}],
			matchExecutable: () => false,
		});

		assert.equal(
			scanner.matchDarwinProcess({pid: 1, path: '/usr/bin/tool', args: ['/usr/bin/tool']}),
			null,
		);
	});
});
