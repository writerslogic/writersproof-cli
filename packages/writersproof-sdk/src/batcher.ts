// SPDX-License-Identifier: AGPL-3.0-only
import { WritersProofClient } from "./client.js";
import type { ContentEvent } from "./types.js";
import type { Logger } from "./logger.js";

export interface BatcherOptions {
	maxBatchSize?: number;
	flushIntervalMs?: number;
	logger?: Logger;
}

export class EventBatcher {
	private queues = new Map<string, ContentEvent[]>();
	private timer: ReturnType<typeof setInterval> | null = null;
	private readonly client: WritersProofClient;
	private readonly maxBatchSize: number;
	private readonly flushIntervalMs: number;
	private readonly logger?: Logger;

	constructor(client: WritersProofClient, options: BatcherOptions = {}) {
		this.client = client;
		this.maxBatchSize = options.maxBatchSize ?? 10;
		this.flushIntervalMs = options.flushIntervalMs ?? 5000;
		this.logger = options.logger;
	}

	addEvent(sessionId: string, event: ContentEvent): void {
		const queue = this.queues.get(sessionId) ?? [];
		queue.push(event);
		this.queues.set(sessionId, queue);

		if (queue.length >= this.maxBatchSize) {
			this.logger?.debug("Batch size reached, flushing", {
				sessionId,
				count: queue.length,
			});
			void this.flush(sessionId);
		}
	}

	async flush(sessionId?: string): Promise<void> {
		const targets = sessionId
			? [sessionId]
			: Array.from(this.queues.keys());

		const promises = targets.map(async (sid) => {
			const events = this.queues.get(sid);
			if (!events || events.length === 0) return;

			const batch = events.splice(0, events.length);
			if (events.length === 0) this.queues.delete(sid);

			try {
				await this.client.submitEvents(sid, batch);
				this.logger?.debug("Flushed batch", {
					sessionId: sid,
					count: batch.length,
				});
			} catch (err) {
				this.logger?.error("Failed to flush batch, re-queuing", {
					sessionId: sid,
					count: batch.length,
					error: String(err),
				});
				const existing = this.queues.get(sid) ?? [];
				this.queues.set(sid, [...batch, ...existing]);
			}
		});

		await Promise.allSettled(promises);
	}

	start(): void {
		if (this.timer) return;
		this.timer = setInterval(() => {
			void this.flush();
		}, this.flushIntervalMs);
		this.logger?.info("Event batcher started", {
			flushIntervalMs: this.flushIntervalMs,
		});
	}

	async stop(): Promise<void> {
		if (this.timer) {
			clearInterval(this.timer);
			this.timer = null;
		}
		await this.flush();
		this.logger?.info("Event batcher stopped");
	}
}
