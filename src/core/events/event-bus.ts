/* eslint-disable unicorn/prefer-event-target */
import { EventEmitter } from 'node:events';

import type { WebhookEventEnvelope } from './event-catalog';
import { buildEventEnvelope } from './event-catalog';

export class AppEventBus extends EventEmitter {
  private static instance: AppEventBus;

  private constructor() {
    super();
    // Allow high concurrency for listener execution
    this.setMaxListeners(50);
  }

  public static getInstance(): AppEventBus {
    if (!AppEventBus.instance) {
      AppEventBus.instance = new AppEventBus();
    }
    return AppEventBus.instance;
  }

  public publish<T = Record<string, unknown>>(
    eventType: string,
    data: T,
    eventId?: string
  ): WebhookEventEnvelope<T> {
    const envelope = buildEventEnvelope(eventType, data, eventId);

    // Asynchronously dispatch without blocking caller
    setImmediate(() => {
      try {
        this.emit('domain_event', envelope);
        this.emit(eventType, envelope);
      } catch (error) {
        // Prevent background event emission errors from crashing core process
        // eslint-disable-next-line no-console
        console.error(`[EventBus] Unhandled error during event publication (${eventType}):`, error);
      }
    });

    return envelope;
  }
}

export const eventBus = AppEventBus.getInstance();
