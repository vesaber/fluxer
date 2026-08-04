// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict';
import {execFile as realExecFile} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import {describe, test} from 'node:test';
import {fileURLToPath} from 'node:url';
import {promisify} from 'node:util';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const esbuild = require('esbuild');

const sourcePath = fileURLToPath(new URL('../WindowsProcessScanner.ts', import.meta.url));
const transformedSource = esbuild.transformSync(readFileSync(sourcePath, 'utf8'), {
	loader: 'ts',
	format: 'cjs',
	platform: 'node',
	target: 'node20',
}).code;

const ANTI_CHEAT_EXECUTABLES = ['easyanticheat', 'battleye', 'vanguard'];

function makeExecError(message, code) {
	const error = new Error(message);
	error.code = code;
	return error;
}

function plain(value) {
	return JSON.parse(JSON.stringify(value));
}

function loadWindowsProcessScanner({execFile, matchApp = () => null}) {
	const calls = [];
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
		process: {platform: 'win32'},
		require: (specifier) => {
			if (specifier === 'node:child_process') return {execFile: execFileStub};
			if (specifier === 'electron-log') return {info() {}, warn() {}, error() {}};
			if (specifier === '@electron/main/DetectableApplications') {
				return {matchAppByWindowsCmdline: matchApp};
			}
			if (specifier === '@electron/main/rpc/RpcConstants') {
				return {PROCESS_QUERY_MAX_BUFFER_BYTES: 4 * 1024 * 1024, PROCESS_QUERY_TIMEOUT: 10000};
			}
			if (specifier === '@electron/main/rpc/ProcessScanState') {
				return {
					isIgnoredPath: (value) => {
						const lower = value.toLowerCase();
						return ANTI_CHEAT_EXECUTABLES.some((name) => lower.includes(name));
					},
				};
			}
			return require(specifier);
		},
	});
	vm.runInContext(transformedSource, context, {filename: sourcePath});
	return {...module.exports, calls};
}

function respondWith(stdout) {
	return (_file, _args, _options, callback) => callback(null, stdout, '');
}

describe('WindowsProcessScanner', () => {
	test('parses CIM JSON output into scanned processes', () => {
		const scanner = loadWindowsProcessScanner({execFile: respondWith('')});
		const processes = scanner.parseCimProcessOutput(
			JSON.stringify([
				{
					ProcessId: 4242,
					ExecutablePath: 'C:\\Games\\Celeste\\Celeste.exe',
					CommandLine: '"C:\\Games\\Celeste\\Celeste.exe" --fullscreen',
				},
			]),
		);

		assert.deepEqual(plain(processes), [
			{
				pid: 4242,
				path: 'C:\\Games\\Celeste\\Celeste.exe',
				args: ['C:\\Games\\Celeste\\Celeste.exe', '"C:\\Games\\Celeste\\Celeste.exe" --fullscreen'],
			},
		]);
	});

	test('skips system processes reporting null path and command line', () => {
		const scanner = loadWindowsProcessScanner({execFile: respondWith('')});
		const processes = scanner.parseCimProcessOutput(
			JSON.stringify([
				{ProcessId: 0, ExecutablePath: null, CommandLine: null},
				{ProcessId: 4, ExecutablePath: null, CommandLine: null},
				{ProcessId: 900, ExecutablePath: 'C:\\Windows\\explorer.exe', CommandLine: null},
			]),
		);

		assert.deepEqual(
			plain(processes.map((entry) => entry.pid)),
			[900],
		);
	});

	test('normalizes a single-process object into an array', () => {
		const scanner = loadWindowsProcessScanner({execFile: respondWith('')});
		const processes = scanner.parseCimProcessOutput(
			JSON.stringify({ProcessId: 77, ExecutablePath: 'C:\\a\\b.exe', CommandLine: 'b.exe'}),
		);

		assert.equal(processes.length, 1);
		assert.equal(processes[0].pid, 77);
	});

	test('drops anti-cheat processes before they reach the matcher', () => {
		const scanner = loadWindowsProcessScanner({execFile: respondWith('')});
		const processes = scanner.parseCimProcessOutput(
			JSON.stringify([
				{ProcessId: 10, ExecutablePath: 'C:\\Game\\EasyAntiCheat.exe', CommandLine: 'EasyAntiCheat.exe'},
				{ProcessId: 11, ExecutablePath: 'C:\\Game\\game.exe', CommandLine: 'game.exe'},
			]),
		);

		assert.deepEqual(
			plain(processes.map((entry) => entry.pid)),
			[11],
		);
	});

	test('returns empty on malformed JSON instead of throwing', () => {
		const scanner = loadWindowsProcessScanner({execFile: respondWith('')});
		assert.deepEqual(plain(scanner.parseCimProcessOutput('not json at all')), []);
		assert.deepEqual(plain(scanner.parseCimProcessOutput('')), []);
	});

	test('queries powershell with bounded buffer and timeout', async () => {
		const scanner = loadWindowsProcessScanner({
			execFile: respondWith(JSON.stringify([{ProcessId: 5, ExecutablePath: 'C:\\x.exe', CommandLine: 'x.exe'}])),
		});

		const processes = await scanner.enumerateWindowsProcesses();

		assert.equal(processes.length, 1);
		assert.equal(scanner.calls.length, 1);
		const [call] = scanner.calls;
		assert.equal(call.file, 'powershell.exe');
		assert.deepEqual(plain(call.args.slice(0, 3)), ['-NoProfile', '-NonInteractive', '-Command']);
		assert.match(call.args[3], /^Get-CimInstance Win32_Process \|/);
		assert.equal(call.options.maxBuffer, 4 * 1024 * 1024);
		assert.equal(call.options.timeout, 10000);
		assert.equal(call.options.windowsHide, true);
	});

	test('returns empty when powershell is unavailable', async () => {
		const scanner = loadWindowsProcessScanner({
			execFile: (_file, _args, _options, callback) => callback(makeExecError('spawn ENOENT', 'ENOENT'), '', ''),
		});

		assert.deepEqual(plain(await scanner.enumerateWindowsProcesses()), []);
	});

	test('returns empty when output exceeds maxBuffer', async () => {
		const scanner = loadWindowsProcessScanner({
			execFile: (_file, _args, _options, callback) =>
				callback(makeExecError('stdout maxBuffer length exceeded', 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER'), '', ''),
		});

		assert.deepEqual(plain(await scanner.enumerateWindowsProcesses()), []);
	});

	test('forwards the executable path and command line to the matcher', () => {
		const seen = [];
		const scanner = loadWindowsProcessScanner({
			execFile: respondWith(''),
			matchApp: (args) => {
				seen.push(args);
				return {id: 'celeste', name: 'Celeste'};
			},
		});

		const app = scanner.matchWindowsProcess({
			pid: 1,
			path: 'C:\\Games\\Celeste\\Celeste.exe',
			args: ['C:\\Games\\Celeste\\Celeste.exe', 'Celeste.exe --fullscreen'],
		});

		assert.deepEqual(plain(app), {id: 'celeste', name: 'Celeste'});
		assert.deepEqual(plain(seen), [['C:\\Games\\Celeste\\Celeste.exe', 'Celeste.exe --fullscreen']]);
	});

	test('enumerates real processes on this machine', {skip: process.platform !== 'win32'}, async () => {
		const scanner = loadWindowsProcessScanner({execFile: realExecFile});

		const processes = await scanner.enumerateWindowsProcesses();

		assert.ok(processes.length > 10, `expected a populated process list, got ${processes.length}`);
		assert.ok(
			processes.every((entry) => Number.isInteger(entry.pid) && entry.pid > 0),
			'every entry should carry a usable pid',
		);
		assert.ok(
			processes.some((entry) => entry.args.some((arg) => arg.toLowerCase().includes('.exe'))),
			'expected at least one process to expose an .exe in its path or command line',
		);
	});
});
