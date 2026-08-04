// SPDX-License-Identifier: AGPL-3.0-or-later

import log from 'electron-log';
import {enumerateDarwinProcesses, matchDarwinProcess} from '@electron/main/DarwinProcessScanner';
import {loadDetectableApplications} from '@electron/main/DetectableApplications';
import {enumerateLinuxProcesses, matchLinuxProcess} from '@electron/main/LinuxProcessScanner';
import {enumerateWindowsProcesses, matchWindowsProcess} from '@electron/main/WindowsProcessScanner';
import {PROCESS_SCAN_INTERVAL} from '@electron/main/rpc/RpcConstants';
import {
	expireMissingApps,
	recordDetectedApp,
	resetScanState,
	syncPrimaryGame,
	type ScannedProcess,
} from '@electron/main/rpc/ProcessScanState';
import type {DetectableApp} from '@electron/main/rpc/RpcTypes';

interface PlatformScanner {
	enumerate: () => Promise<Array<ScannedProcess>>;
	match: (scanned: ScannedProcess) => DetectableApp | null;
}

const PLATFORM_SCANNERS: Partial<Record<NodeJS.Platform, PlatformScanner>> = {
	linux: {enumerate: enumerateLinuxProcesses, match: matchLinuxProcess},
	win32: {enumerate: enumerateWindowsProcesses, match: matchWindowsProcess},
	darwin: {enumerate: enumerateDarwinProcesses, match: matchDarwinProcess},
};

let scanTimer: NodeJS.Timeout | null = null;
let isScanning = false;

export async function runProcessScan(scanner: PlatformScanner): Promise<void> {
	const processes = await scanner.enumerate();
	const activeIds = new Set<string>();
	for (const scanned of processes) {
		const app = scanner.match(scanned);
		if (!app) continue;
		activeIds.add(app.id);
		recordDetectedApp(app, scanned.pid);
	}
	expireMissingApps(activeIds);
	syncPrimaryGame(activeIds);
}

async function scan(scanner: PlatformScanner): Promise<void> {
	if (isScanning) return;
	isScanning = true;
	try {
		await runProcessScan(scanner);
	} catch (error) {
		log.error('[RPC] Process scan failed:', error);
	} finally {
		isScanning = false;
	}
}

export function startProcessScanner(): void {
	if (scanTimer) return;
	const scanner = PLATFORM_SCANNERS[process.platform];
	if (!scanner) return;
	loadDetectableApplications();
	scanTimer = setInterval(() => void scan(scanner), PROCESS_SCAN_INTERVAL);
	void scan(scanner);
	log.info('[RPC] ProcessScanner started', process.platform);
}

export function stopProcessScanner(): void {
	if (scanTimer) {
		clearInterval(scanTimer);
		scanTimer = null;
	}
	resetScanState();
}
