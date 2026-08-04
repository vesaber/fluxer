// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import {describe, test} from 'node:test';
import {fileURLToPath} from 'node:url';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const esbuild = require('esbuild');

const sourcePath = fileURLToPath(new URL('../rpc/ProcessScanState.ts', import.meta.url));
const transformedSource = esbuild.transformSync(readFileSync(sourcePath, 'utf8'), {
	loader: 'ts',
	format: 'cjs',
	platform: 'node',
	target: 'node20',
}).code;

function plain(value) {
	return JSON.parse(JSON.stringify(value));
}

function loadProcessScanState({executableIndex = new Map()} = {}) {
	const emitted = [];
	const clock = {now: 1_000_000};
	const module = {exports: {}};
	const context = vm.createContext({
		module,
		exports: module.exports,
		console,
		Date: {now: () => clock.now},
		require: (specifier) => {
			if (specifier === 'electron-log') return {info() {}, warn() {}, error() {}};
			if (specifier === '@electron/main/ArRpcServer') {
				return {
					emitSyntheticActivity: (activity, pid) => emitted.push({activity, pid}),
				};
			}
			if (specifier === '@electron/main/DetectableApplications') {
				return {getExecutableIndex: () => executableIndex};
			}
			if (specifier === '@electron/main/rpc/RpcConstants') {
				return {
					ANTI_CHEAT_EXECUTABLES: ['easyanticheat', 'battleye', 'vanguard'],
					EXECUTABLE_ARCH_SUFFIXES: ['64', '.x64', 'x64', '_64'],
					LOST_GAME_MISS_THRESHOLD: 2,
				};
			}
			return require(specifier);
		},
	});
	vm.runInContext(transformedSource, context, {filename: sourcePath});
	return {...module.exports, emitted, clock};
}

describe('ProcessScanState', () => {
	test('exposes a detected app by the pid that was seen', () => {
		const state = loadProcessScanState();

		state.recordDetectedApp({id: 'celeste', name: 'Celeste'}, 4242);

		assert.equal(state.getScannedGameIdByPid(4242), 'celeste');
		assert.equal(state.getScannedGameIdByPid(9999), null);
	});

	test('tolerates one missed scan before dropping an app', () => {
		const state = loadProcessScanState();
		state.recordDetectedApp({id: 'celeste', name: 'Celeste'}, 1);

		state.expireMissingApps(new Set());
		assert.equal(state.getScannedGameIdByPid(1), 'celeste');

		state.expireMissingApps(new Set());
		assert.equal(state.getScannedGameIdByPid(1), null);
	});

	test('resets the miss counter when an app is seen again', () => {
		const state = loadProcessScanState();
		state.recordDetectedApp({id: 'celeste', name: 'Celeste'}, 1);

		state.expireMissingApps(new Set());
		state.recordDetectedApp({id: 'celeste', name: 'Celeste'}, 1);
		state.expireMissingApps(new Set());

		assert.equal(state.getScannedGameIdByPid(1), 'celeste');
	});

	test('follows an app across a pid change without re-announcing it', () => {
		const state = loadProcessScanState();
		state.recordDetectedApp({id: 'celeste', name: 'Celeste'}, 1);
		state.syncPrimaryGame(new Set(['celeste']));

		state.recordDetectedApp({id: 'celeste', name: 'Celeste'}, 77);
		state.syncPrimaryGame(new Set(['celeste']));

		assert.equal(state.getScannedGameIdByPid(77), 'celeste');
		assert.equal(state.emitted.length, 1);
	});

	test('emits the most recently started app as the primary activity', () => {
		const state = loadProcessScanState();
		state.recordDetectedApp({id: 'celeste', name: 'Celeste'}, 1);
		state.clock.now += 5000;
		state.recordDetectedApp({id: 'osu', name: 'osu!'}, 2);

		state.syncPrimaryGame(new Set(['celeste', 'osu']));

		assert.equal(state.emitted.length, 1);
		const [{activity, pid}] = state.emitted;
		assert.equal(activity.name, 'osu!');
		assert.equal(activity.application_id, 'osu');
		assert.equal(activity.type, 0);
		assert.equal(pid, 2);
	});

	test('reports activity start as whole seconds', () => {
		const state = loadProcessScanState();
		state.clock.now = 1_700_000_123_456;
		state.recordDetectedApp({id: 'celeste', name: 'Celeste'}, 1);

		state.syncPrimaryGame(new Set(['celeste']));

		assert.equal(state.emitted[0].activity.timestamps.start, 1_700_000_123);
	});

	test('stays silent while the primary app is unchanged', () => {
		const state = loadProcessScanState();
		state.recordDetectedApp({id: 'celeste', name: 'Celeste'}, 1);

		state.syncPrimaryGame(new Set(['celeste']));
		state.syncPrimaryGame(new Set(['celeste']));
		state.syncPrimaryGame(new Set(['celeste']));

		assert.equal(state.emitted.length, 1);
	});

	test('clears the activity once nothing is running', () => {
		const state = loadProcessScanState();
		state.recordDetectedApp({id: 'celeste', name: 'Celeste'}, 1);
		state.syncPrimaryGame(new Set(['celeste']));

		state.syncPrimaryGame(new Set());

		assert.equal(state.emitted.length, 2);
		assert.equal(state.emitted[1].activity, null);
	});

	test('does not send a redundant clear when nothing was ever emitted', () => {
		const state = loadProcessScanState();

		state.syncPrimaryGame(new Set());

		assert.equal(state.emitted.length, 0);
	});

	test('forgets everything on reset', () => {
		const state = loadProcessScanState();
		state.recordDetectedApp({id: 'celeste', name: 'Celeste'}, 1);
		state.syncPrimaryGame(new Set(['celeste']));

		state.resetScanState();

		assert.equal(state.getScannedGameIdByPid(1), null);
		state.syncPrimaryGame(new Set());
		assert.equal(state.emitted.length, 1);
	});

	test('ignores anti-cheat executables anywhere in the path', () => {
		const state = loadProcessScanState();

		assert.equal(state.isIgnoredPath('C:/Games/Rust/EasyAntiCheat/EasyAntiCheat.exe'), true);
		assert.equal(state.isIgnoredPath('/usr/games/battleye/beclient'), true);
		assert.equal(state.isIgnoredPath('/usr/games/celeste/celeste'), false);
	});

	test('offers architecture-stripped variations so 64-bit binaries match base rules', () => {
		const state = loadProcessScanState();

		const variations = state.generatePathVariations('games/celeste/celeste64.exe');

		assert.ok(variations.includes('celeste64.exe'));
		assert.ok(variations.includes('celeste.exe'), 'the 64 suffix should also be offered stripped');
		assert.ok(variations.includes('celeste/celeste64.exe'));
		assert.equal(variations[0], 'celeste64.exe', 'the basename must stay first');
	});

	test('collects candidates by full suffix and by extension-less basename', () => {
		const celeste = {id: 'celeste', name: 'Celeste'};
		const osu = {id: 'osu', name: 'osu!'};
		const state = loadProcessScanState({
			executableIndex: new Map([
				['celeste/celeste.exe', [celeste]],
				['osu!', [osu]],
			]),
		});

		const candidates = state.getCandidateApps(['celeste/celeste.exe', 'osu!.exe']);

		assert.deepEqual(
			plain(candidates).map((app) => app.id),
			['celeste', 'osu'],
		);
	});
});
