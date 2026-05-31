// SPDX-License-Identifier: AGPL-3.0-only
import crypto from "crypto";

export function verifyWebhookSignature(
	payload: Buffer | string,
	signature: string,
	secret: string,
	algorithm: "sha256" | "sha1" = "sha256",
): boolean {
	const expected = crypto
		.createHmac(algorithm, secret)
		.update(typeof payload === "string" ? payload : payload)
		.digest("hex");

	if (expected.length !== signature.length) return false;
	return crypto.timingSafeEqual(
		Buffer.from(expected),
		Buffer.from(signature),
	);
}
