import { describe, it, expect, vi, beforeEach } from "vitest";
import {
	WritersProofClient,
	hashContent,
} from "../src/services/WritersProofClient.js";

describe("WritersProofClient", () => {
	let client: WritersProofClient;

	beforeEach(() => {
		client = new WritersProofClient(
			"test-key",
			"ghost",
			"http://localhost:9999",
		);
	});

	it("throws on missing apiKey", () => {
		expect(() => new WritersProofClient("", "ghost")).toThrow(
			"apiKey is required",
		);
	});

	it("throws on missing platform", () => {
		expect(() => new WritersProofClient("key", "")).toThrow(
			"platform is required",
		);
	});

	describe("hashContent", () => {
		it("produces consistent SHA-256 hex", () => {
			const hash = hashContent("hello world");
			expect(hash).toBe(
				"b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
			);
			expect(hash).toMatch(/^[a-f0-9]{64}$/);
		});

		it("produces different hashes for different input", () => {
			expect(hashContent("a")).not.toBe(hashContent("b"));
		});

		it("handles empty string", () => {
			const hash = hashContent("");
			expect(hash).toMatch(/^[a-f0-9]{64}$/);
		});
	});

	describe("createSession", () => {
		it("calls POST /sessions with correct body", async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				ok: true,
				status: 200,
				json: () =>
					Promise.resolve({
						id: "session-1",
						documentId: "doc-1",
						documentTitle: "Test",
						platform: "ghost",
						contentHash: "abc",
						createdAt: "2026-01-01",
					}),
			});
			vi.stubGlobal("fetch", mockFetch);

			const session = await client.createSession({
				documentId: "doc-1",
				documentTitle: "Test Post",
				contentHash: "abc123",
			});

			expect(session.id).toBe("session-1");
			expect(mockFetch).toHaveBeenCalledWith(
				"http://localhost:9999/sessions",
				expect.objectContaining({
					method: "POST",
					headers: expect.objectContaining({
						Authorization: "Bearer test-key",
						"X-Client-Platform": "ghost",
					}),
				}),
			);

			vi.unstubAllGlobals();
		});
	});

	describe("retry behavior", () => {
		it("retries on 500 with exponential backoff", async () => {
			let attempts = 0;
			const mockFetch = vi.fn().mockImplementation(() => {
				attempts++;
				if (attempts <= 2) {
					return Promise.resolve({
						ok: false,
						status: 500,
						text: () => Promise.resolve("Server Error"),
					});
				}
				return Promise.resolve({
					ok: true,
					status: 200,
					json: () => Promise.resolve({ id: "ok" }),
				});
			});
			vi.stubGlobal("fetch", mockFetch);

			const result = await client.createSession({
				documentId: "x",
				documentTitle: "x",
				contentHash: "x",
			});
			expect(result.id).toBe("ok");
			expect(attempts).toBe(3);

			vi.unstubAllGlobals();
		});

		it("handles 429 with Retry-After header", async () => {
			let attempts = 0;
			const mockFetch = vi.fn().mockImplementation(() => {
				attempts++;
				if (attempts === 1) {
					return Promise.resolve({
						ok: false,
						status: 429,
						headers: new Map([["Retry-After", "1"]]) as any,
					});
				}
				return Promise.resolve({
					ok: true,
					status: 200,
					json: () => Promise.resolve({ id: "ok" }),
				});
			});
			vi.stubGlobal("fetch", mockFetch);

			const result = await client.createSession({
				documentId: "x",
				documentTitle: "x",
				contentHash: "x",
			});
			expect(result.id).toBe("ok");

			vi.unstubAllGlobals();
		});
	});
});
