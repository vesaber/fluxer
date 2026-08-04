// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import {describe, test} from 'node:test';
import {fileURLToPath} from 'node:url';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const esbuild = require('esbuild');

const sourcePath = fileURLToPath(new URL('../ProcessScanner.ts', import.meta.url));
const transformedSource = esbuild.transformSync(readFileSync(sourcePath, 'utf8'), {
	loader: 'ts',
	format: 'cjs',
	platform: 'node',
	target: 'node20',
}).code;

function loadProcessScanner({platform = 'linux', enumerators = {}} = {}) {
	const events = [];
	const platformModule = (name) => ({
		[`enumerate${name}Processes`]: () => {
			events.push({enumerated: name});
			const enumerate = enumerators[name.toLowerCase()];
			return Promise.resolve(enumerate ? enumerate() : []);
		},
		[`match${name}Process`]: (scanned) => scanned.app ?? null,
	});
	const module = {exports: {}};
	const context = vm.createContext({
		module,
		exports: module.exports,
		console,
		process: {platform},
		setInterval,
		clearInterval,
		require: (specifier) => {
			if (specifier === 'electron-log') return {info() {}, warn() {}, error() {}};
			if (specifier === '@electron/main/LinuxProcessScanner') return platformModule('Linux');
			if (specifier === '@electron/main/WindowsProcessScanner') return platformModule('Windows');
			if (specifier === '@electron/main/DarwinProcessScanner') return platformModule('Darwin');
			if (specifier === '@electron/main/DetectableApplications') {
				return {
					loadDetectableApplications: () => events.push({loaded: true}),
				};
			}
			if (specifier === '@electron/main/rpc/RpcConstants') {
				return {PROCESS_SCAN_INTERVAL: 15000};
			}
			if (specifier === '@electron/main/rpc/ProcessScanState') {
				return {
					recordDetectedApp: (app, pid) => events.push({recorded: app.id, pid}),
					expireMissingApps: (activeIds) => events.push({expired: [...activeIds]}),
					syncPrimaryGame: (activeIds) => events.push({synced: [...activeIds]}),
					resetScanState: () => events.push({reset: true}),
				};
			}
			return require(specifier);
		},
	});
	vm.runInContext(transformedSource, context, {filename: sourcePath});
	return {...module.exports, events};
}

const flush = () => new Promise((resolve) => setImmediate(resolve));

describe('ProcessScanner', () => {
	test('records each matched process then expires and syncs once per scan', async () => {
		const scanner = loadProcessScanner();

		await scanner.runProcessScan({
			enumerate: () =>
				Promise.resolve([
					{pid: 1, app: {id: 'celeste', name: 'Celeste'}},
					{pid: 2, app: null},
					{pid: 3, app: {id: 'osu', name: 'osu!'}},
				]),
			match: (scanned) => scanned.app,
		});

		assert.deepEqual(scanner.events, [
			{recorded: 'celeste', pid: 1},
			{recorded: 'osu', pid: 3},
			{expired: ['celeste', 'osu']},
			{synced: ['celeste', 'osu']},
		]);
	});

	test('still expires and syncs when nothing is detected', async () => {
		const scanner = loadProcessScanner();

		await scanner.runProcessScan({enumerate: () => Promise.resolve([]), match: () => null});

		assert.deepEqual(scanner.events, [{expired: []}, {synced: []}]);
	});

	test('counts a repeated app once per scan', async () => {
		const scanner = loadProcessScanner();
		const app = {id: 'celeste', name: 'Celeste'};

		await scanner.runProcessScan({
			enumerate: () => Promise.resolve([{pid: 1, app}, {pid: 2, app}]),
			match: (scanned) => scanned.app,
		});

		assert.deepEqual(scanner.events.at(-1), {synced: ['celeste']});
	});

	test('selects the scanner for the running platform', async () => {
		for (const [platform, expected] of [
			['linux', 'Linux'],
			['win32', 'Windows'],
			['darwin', 'Darwin'],
		]) {
			const scanner = loadProcessScanner({platform});

			scanner.startProcessScanner();
			await flush();
			scanner.stopProcessScanner();

			assert.ok(
				scanner.events.some((event) => event.enumerated === expected),
				`${platform} should use the ${expected} enumerator`,
			);
		}
	});

	test('does nothing on a platform without a scanner', async () => {
		const scanner = loadProcessScanner({platform: 'aix'});

		scanner.startProcessScanner();
		await flush();

		assert.deepEqual(scanner.events, []);
	});

	test('loads the detectable catalog before the first scan', async () => {
		const scanner = loadProcessScanner({platform: 'win32'});

		scanner.startProcessScanner();
		await flush();
		scanner.stopProcessScanner();

		assert.deepEqual(scanner.events[0], {loaded: true});
	});

	test('survives an enumerator that throws and resets state on stop', async () => {
		const scanner = loadProcessScanner({
			platform: 'win32',
			enumerators: {
				windows: () => {
					throw new Error('powershell exploded');
				},
			},
		});

		scanner.startProcessScanner();
		await flush();
		scanner.stopProcessScanner();

		assert.deepEqual(scanner.events.at(-1), {reset: true});
	});

	test('ignores a second start while already running', async () => {
		const scanner = loadProcessScanner({platform: 'win32'});

		scanner.startProcessScanner();
		scanner.startProcessScanner();
		await flush();
		scanner.stopProcessScanner();

		assert.equal(scanner.events.filter((event) => event.enumerated === 'Windows').length, 1);
	});
});
