import { describe, it, expect } from "vitest";
import { ContentMonitor } from "../src/services/ContentMonitor.js";

describe("ContentMonitor", () => {
	it("throws on missing ghostUrl", () => {
		expect(() => new ContentMonitor("", "key")).toThrow(
			"ghostUrl is required",
		);
	});

	it("throws on missing adminApiKey", () => {
		expect(() => new ContentMonitor("http://ghost.local", "")).toThrow(
			"adminApiKey is required",
		);
	});
});
