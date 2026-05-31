// SPDX-License-Identifier: AGPL-3.0-only
export function requireEnv(name: string): string {
	const value = process.env[name];
	if (!value)
		throw new Error(`Missing required environment variable: ${name}`);
	return value;
}

export function validateHash(hash: string): boolean {
	return /^[a-f0-9]{64}$/.test(hash);
}

export function validateSessionId(id: string): boolean {
	return id.length > 0 && id.length <= 128;
}
