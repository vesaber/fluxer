// SPDX-License-Identifier: AGPL-3.0-or-later

import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import log from 'electron-log';
import {matchLinuxExecutable} from '@electron/main/DetectableApplications';
import {PROCESS_QUERY_MAX_BUFFER_BYTES, PROCESS_QUERY_TIMEOUT} from '@electron/main/rpc/RpcConstants';
import {
	generatePathVariations,
	getCandidateApps,
	isIgnoredPath,
	type ScannedProcess,
} from '@electron/main/rpc/ProcessScanState';
import type {DetectableApp} from '@electron/main/rpc/RpcTypes';

const execFileAsync = promisify(execFile);
// `comm` and `args` are queried separately because macOS paths contain spaces, which makes a
// combined `pid=,comm=,args=` row impossible to split unambiguously.
const PS_COMM_FORMAT = 'pid=,comm=';
const PS_ARGS_FORMAT = 'pid=,args=';
const PS_LINE = /^\s*(\d+)\s+(.+)$/;
const APP_BUNDLE_SEGMENT = '.app';

export function parsePsColumn(stdout: string): Map<number, string> {
	const values = new Map<number, string>();
	for (const line of stdout.split(/\r?\n/)) {
		const match = line.match(PS_LINE);
		if (!match) continue;
		const [, pidRaw, value] = match;
		const pid = Number.parseInt(pidRaw, 10);
		if (!Number.isInteger(pid) || pid <= 0) continue;
		const trimmed = value.trim();
		if (!trimmed) continue;
		values.set(pid, trimmed);
	}
	return values;
}

export function appBundleVariations(normalizedPath: string): Array<string> {
	const bundles: Array<string> = [];
	for (const segment of normalizedPath.split('/')) {
		if (segment.endsWith(APP_BUNDLE_SEGMENT)) {
			bundles.push(segment);
		}
	}
	return bundles;
}

async function runPs(format: string): Promise<Map<number, string>> {
	const {stdout} = await execFileAsync('ps', ['-axo', format], {
		maxBuffer: PROCESS_QUERY_MAX_BUFFER_BYTES,
		timeout: PROCESS_QUERY_TIMEOUT,
	});
	return parsePsColumn(stdout);
}

export async function enumerateDarwinProcesses(): Promise<Array<ScannedProcess>> {
	let executables: Map<number, string>;
	let commandLines: Map<number, string>;
	try {
		[executables, commandLines] = await Promise.all([runPs(PS_COMM_FORMAT), runPs(PS_ARGS_FORMAT)]);
	} catch (error) {
		log.warn('[RPC] macOS process query failed:', error);
		return [];
	}
	const processes: Array<ScannedProcess> = [];
	for (const [pid, executablePath] of executables) {
		if (isIgnoredPath(executablePath)) continue;
		const commandLine = commandLines.get(pid);
		processes.push({
			pid,
			path: executablePath,
			args: commandLine ? [commandLine] : [executablePath],
		});
	}
	return processes;
}

export function matchDarwinProcess(scanned: ScannedProcess): DetectableApp | null {
	const normalized = scanned.path.toLowerCase();
	const variations = generatePathVariations(normalized);
	variations.push(...appBundleVariations(normalized));
	for (const app of getCandidateApps(variations)) {
		if (!app.executables) continue;
		if (app.executables.some((exe) => matchLinuxExecutable(exe, variations, scanned.args, 'darwin'))) {
			return app;
		}
	}
	return null;
}
