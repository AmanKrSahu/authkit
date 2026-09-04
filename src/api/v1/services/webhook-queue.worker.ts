import prisma from '@core/database/prisma';
import { WebhookDeliveryStatus } from '@prisma/client';

import { WebhookService } from './webhook.service';

export class WebhookQueueWorker {
  private webhookService: WebhookService;
  private intervalId: NodeJS.Timeout | null = null;
  private isProcessing = false;

  constructor(webhookService: WebhookService = new WebhookService()) {
    this.webhookService = webhookService;
  }

  public start(intervalMs = 5000): void {
    if (this.intervalId) return;

    this.intervalId = setInterval(() => {
      this.processPendingJobs().catch(() => {
        // Non-blocking catch
      });
    }, intervalMs);
  }

  public stop(): void {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
  }

  public async processPendingJobs(): Promise<number> {
    if (this.isProcessing) return 0;
    this.isProcessing = true;

    try {
      const now = new Date();

      const pendingDeliveries = await prisma.webhookDelivery.findMany({
        where: {
          status: WebhookDeliveryStatus.PENDING,
          OR: [{ nextRetryAt: null }, { nextRetryAt: { lte: now } }],
        },
        take: 50,
        orderBy: { createdAt: 'asc' },
      });

      if (pendingDeliveries.length === 0) {
        return 0;
      }

      for (const delivery of pendingDeliveries) {
        await this.webhookService.processDeliveryAttempt({ deliveryId: delivery.id });
      }

      return pendingDeliveries.length;
    } finally {
      this.isProcessing = false;
    }
  }
}
