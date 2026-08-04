// SPDX-License-Identifier: AGPL-3.0-or-later

import log from 'electron-log';
import {emitSyntheticActivity} from '@electron/main/ArRpcServer';
import {getExecutableIndex} from '@electron/main/DetectableApplications';
import {
	ANTI_CHEAT_EXECUTABLES,
	EXECUTABLE_ARCH_SUFFIXES,
	LOST_GAME_MISS_THRESHOLD,
} from '@electron/main/rpc/RpcConstants';
import type {DetectableApp} from '@electron/main/rpc/RpcTypes';

export interface ScannedProcess {
	pid: number;
	path: string;
	args: Array<string>;
}

interface GameState {
	name: string;
	pid: number;
	timestamp: number;
	missedScans: number;
}

const gameState = new Map<string, GameState>();
let lastEmittedPrimaryId: string | null = null;

export function getScannedGameIdByPid(pid: number): string | null {
	for (const [id, state] of gameState) {
		if (state.pid === pid) {
			return id;
		}
	}
	return null;
}

export function isIgnoredPath(processPath: string): boolean {
	const lower = processPath.toLowerCase();
	return ANTI_CHEAT_EXECUTABLES.some((name) => lower.includes(name));
}

export function generatePathVariations(normalizedPath: string): Array<string> {
	const toCompare: Array<string> = [];
	const splitPath = normalizedPath.split('/');
	for (let i = 1; i <= splitPath.length; i++) {
		toCompare.push(splitPath.slice(-i).join('/'));
	}
	const baseLength = toCompare.length;
	for (let i = 0; i < baseLength; i++) {
		const segment = toCompare[i];
		if (!segment) continue;
		for (const suffix of EXECUTABLE_ARCH_SUFFIXES) {
			if (segment.includes(suffix)) {
				toCompare.push(segment.replace(suffix, ''));
			}
		}
	}
	return toCompare;
}

export function getCandidateApps(pathVariations: Array<string>): Array<DetectableApp> {
	const executableIndex = getExecutableIndex();
	const candidateSet = new Set<DetectableApp>();
	for (const pathVar of pathVariations) {
		const apps = executableIndex.get(pathVar);
		if (apps) {
			for (const candidate of apps) candidateSet.add(candidate);
		}
		const lastSlash = pathVar.lastIndexOf('/');
		const filename = lastSlash >= 0 ? pathVar.slice(lastSlash + 1) : pathVar;
		const dotIndex = filename.lastIndexOf('.');
		if (dotIndex > 0) {
			const withoutExt = filename.slice(0, dotIndex);
			const appsNoExt = executableIndex.get(withoutExt);
			if (appsNoExt) {
				for (const app of appsNoExt) candidateSet.add(app);
			}
		}
	}
	return [...candidateSet];
}

export function recordDetectedApp(app: DetectableApp, pid: number): void {
	const state = gameState.get(app.id);
	if (!state) {
		gameState.set(app.id, {name: app.name, pid, timestamp: Date.now(), missedScans: 0});
		log.info('[RPC] Process scan detected game', app.name);
		return;
	}
	if (state.pid !== pid) {
		state.pid = pid;
	}
	state.missedScans = 0;
}

export function expireMissingApps(activeIds: Set<string>): void {
	for (const [id, state] of gameState) {
		if (activeIds.has(id)) continue;
		state.missedScans += 1;
		if (state.missedScans < LOST_GAME_MISS_THRESHOLD) continue;
		gameState.delete(id);
		log.info('[RPC] Process scan lost game', state.name);
	}
}

function pickPrimaryGameId(activeIds: Set<string>): string | null {
	let primaryId: string | null = null;
	let primaryTimestamp = 0;
	for (const id of activeIds) {
		const state = gameState.get(id);
		if (!state) continue;
		if (state.timestamp > primaryTimestamp) {
			primaryTimestamp = state.timestamp;
			primaryId = id;
		}
	}
	return primaryId;
}

function emitPrimaryGame(id: string): void {
	const state = gameState.get(id);
	if (!state) return;
	emitSyntheticActivity(
		{
			application_id: id,
			name: state.name,
			type: 0,
			timestamps: {start: Math.floor(state.timestamp / 1000)},
			pid: state.pid,
		},
		state.pid,
	);
	lastEmittedPrimaryId = id;
	log.info('[RPC] Process scan active game', state.name);
}

function clearPrimaryGame(): void {
	if (!lastEmittedPrimaryId) return;
	emitSyntheticActivity(null);
	lastEmittedPrimaryId = null;
	log.info('[RPC] Process scan cleared active game');
}

export function syncPrimaryGame(activeIds: Set<string>): void {
	const primaryId = pickPrimaryGameId(activeIds);
	if (primaryId === lastEmittedPrimaryId) {
		return;
	}
	if (primaryId) {
		emitPrimaryGame(primaryId);
		return;
	}
	clearPrimaryGame();
}

export function resetScanState(): void {
	gameState.clear();
	lastEmittedPrimaryId = null;
}
