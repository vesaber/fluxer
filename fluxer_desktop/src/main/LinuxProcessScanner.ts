// SPDX-License-Identifier: AGPL-3.0-or-later

import type {Dirent} from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';
import log from 'electron-log';
import {matchAppByWindowsCmdline, matchLinuxExecutable} from '@electron/main/DetectableApplications';
import {
	CMDLINE_NULL_SEPARATOR,
	LINUX_PROC_DIR,
} from '@electron/main/rpc/RpcConstants';
import {
	generatePathVariations,
	getCandidateApps,
	isIgnoredPath,
	type ScannedProcess,
} from '@electron/main/rpc/ProcessScanState';
import type {DetectableApp} from '@electron/main/rpc/RpcTypes';

export async function enumerateLinuxProcesses(): Promise<Array<ScannedProcess>> {
	let entries: Array<Dirent>;
	try {
		entries = await fs.readdir(LINUX_PROC_DIR, {withFileTypes: true});
	} catch (error) {
		log.warn('[RPC] Linux process query failed:', error);
		return [];
	}
	const processes: Array<ScannedProcess> = [];
	for (const entry of entries) {
		if (!entry.isDirectory() || !/^\d+$/.test(entry.name)) continue;
		const pid = Number.parseInt(entry.name, 10);
		try {
			const cmdline = await fs.readFile(path.join(LINUX_PROC_DIR, entry.name, 'cmdline'), 'utf8');
			if (!cmdline) continue;
			const args = cmdline.split(CMDLINE_NULL_SEPARATOR).filter(Boolean);
			const exePath = args[0] ?? cmdline.replaceAll(CMDLINE_NULL_SEPARATOR, ' ').trim();
			if (!exePath || isIgnoredPath(exePath)) continue;
			processes.push({pid, path: exePath, args});
		} catch {
			continue;
		}
	}
	return processes;
}

export function matchLinuxProcess(scanned: ScannedProcess): DetectableApp | null {
	const normalized = scanned.path.toLowerCase().replaceAll('\\', '/');
	const variations = generatePathVariations(normalized);
	for (const app of getCandidateApps(variations)) {
		if (!app.executables) continue;
		if (app.executables.some((exe) => matchLinuxExecutable(exe, variations, scanned.args, 'linux'))) {
			return app;
		}
	}
	if (scanned.args.some((arg) => /\.exe/i.test(arg))) {
		return matchAppByWindowsCmdline(scanned.args);
	}
	return null;
}
