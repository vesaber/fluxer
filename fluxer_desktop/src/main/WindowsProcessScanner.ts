// SPDX-License-Identifier: AGPL-3.0-or-later

import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import log from 'electron-log';
import {matchAppByWindowsCmdline} from '@electron/main/DetectableApplications';
import {PROCESS_QUERY_MAX_BUFFER_BYTES, PROCESS_QUERY_TIMEOUT} from '@electron/main/rpc/RpcConstants';
import {isIgnoredPath, type ScannedProcess} from '@electron/main/rpc/ProcessScanState';
import type {DetectableApp} from '@electron/main/rpc/RpcTypes';

const execFileAsync = promisify(execFile);
const CIM_PROCESS_QUERY =
	'Get-CimInstance Win32_Process | Select-Object ProcessId,ExecutablePath,CommandLine | ConvertTo-Json -Compress';

interface CimProcessRecord {
	ProcessId?: unknown;
	ExecutablePath?: unknown;
	CommandLine?: unknown;
}

function toRecordArray(parsed: unknown): Array<CimProcessRecord> {
	if (Array.isArray(parsed)) return parsed as Array<CimProcessRecord>;
	if (parsed != null && typeof parsed === 'object') return [parsed as CimProcessRecord];
	return [];
}

function toProcessString(value: unknown): string {
	return typeof value === 'string' ? value : '';
}

export function parseCimProcessOutput(stdout: string): Array<ScannedProcess> {
	const trimmed = stdout.trim();
	if (!trimmed) return [];
	let parsed: unknown;
	try {
		parsed = JSON.parse(trimmed);
	} catch {
		return [];
	}
	const processes: Array<ScannedProcess> = [];
	for (const record of toRecordArray(parsed)) {
		const pid = Number(record.ProcessId);
		if (!Number.isInteger(pid) || pid <= 0) continue;
		const executablePath = toProcessString(record.ExecutablePath);
		const commandLine = toProcessString(record.CommandLine);
		if (!executablePath && !commandLine) continue;
		if (isIgnoredPath(executablePath) || isIgnoredPath(commandLine)) continue;
		processes.push({
			pid,
			path: executablePath,
			args: [executablePath, commandLine].filter(Boolean),
		});
	}
	return processes;
}

export async function enumerateWindowsProcesses(): Promise<Array<ScannedProcess>> {
	try {
		const {stdout} = await execFileAsync(
			'powershell.exe',
			['-NoProfile', '-NonInteractive', '-Command', CIM_PROCESS_QUERY],
			{
				windowsHide: true,
				maxBuffer: PROCESS_QUERY_MAX_BUFFER_BYTES,
				timeout: PROCESS_QUERY_TIMEOUT,
			},
		);
		return parseCimProcessOutput(stdout);
	} catch (error) {
		log.warn('[RPC] Windows process query failed:', error);
		return [];
	}
}

export function matchWindowsProcess(scanned: ScannedProcess): DetectableApp | null {
	return matchAppByWindowsCmdline(scanned.args);
}
