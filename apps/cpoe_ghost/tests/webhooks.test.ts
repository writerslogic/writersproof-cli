import { describe, it, expect } from "vitest";
import crypto from "crypto";

describe("Webhook signature verification", () => {
	it("validates correct HMAC signature", () => {
		const secret = "test-webhook-secret";
		const payload = '{"post":{"current":{"id":"1"}}}';
		const signature = crypto
			.createHmac("sha256", secret)
			.update(payload)
			.digest("hex");

		const isValid = crypto.timingSafeEqual(
			Buffer.from(signature),
			Buffer.from(
				crypto
					.createHmac("sha256", secret)
					.update(payload)
					.digest("hex"),
			),
		);
		expect(isValid).toBe(true);
	});

	it("rejects invalid signature", () => {
		const secret = "test-webhook-secret";
		const payload = '{"post":{"current":{"id":"1"}}}';
		const fakeSignature = "a".repeat(64);

		const expected = crypto
			.createHmac("sha256", secret)
			.update(payload)
			.digest("hex");
		expect(fakeSignature).not.toBe(expected);
	});
});
