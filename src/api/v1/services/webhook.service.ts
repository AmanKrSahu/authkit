import { AppError } from '@core/common/utils/app-error';
import { paginateWithCursor } from '@core/common/utils/pagination';
import { validateWebhookUrl } from '@core/common/utils/ssrf.util';
import {
  calculateBackoffDelayMs,
  executeDeliveryHttp,
  generateSigningSecret,
  MAX_WEBHOOK_RETRIES,
} from '@core/common/utils/webhook.util';
import { HTTPSTATUS } from '@core/config/http.config';
import prisma from '@core/database/prisma';
import { eventBus } from '@core/events/event-bus';
import type { WebhookEventEnvelope } from '@core/events/event-catalog';
import { buildEventEnvelope, isValidEventType } from '@core/events/event-catalog';
import { WebhookDeliveryStatus, WebhookSubscriptionStatus } from '@prisma/client';

import type {
  CreateWebhookSubscriptionData,
  DeleteWebhookSubscriptionData,
  DispatchDomainEventData,
  GetDeliveriesInputData,
  GetDeliveryByIdData,
  GetWebhookByIdData,
  GetWebhooksData,
  ProcessDeliveryAttemptData,
  RotateWebhookSecretData,
  TestWebhookData,
  UpdateWebhookSubscriptionInput,
} from '../../../core/common/interface/webhook.interface';

let isListenerRegistered = false;

export class WebhookService {
  constructor() {
    if (!isListenerRegistered) {
      isListenerRegistered = true;
      eventBus.on('domain_event', (envelope: WebhookEventEnvelope) => {
        this.dispatchDomainEvent({ envelope }).catch(() => {
          // Non-blocking catch
        });
      });
    }
  }

  public async createSubscription(createWebhookSubscriptionData: CreateWebhookSubscriptionData) {
    const { name, url, description, events, createdBy } = createWebhookSubscriptionData;

    await validateWebhookUrl(url);

    for (const eventType of events) {
      if (!isValidEventType(eventType)) {
        throw new AppError(
          `Invalid or unsupported event type: ${eventType}`,
          HTTPSTATUS.BAD_REQUEST
        );
      }
    }

    const secret = generateSigningSecret();

    const subscription = await prisma.webhookSubscription.create({
      data: {
        name,
        url,
        description,
        events,
        secret,
        createdBy,
        status: WebhookSubscriptionStatus.ACTIVE,
      },
    });

    return subscription;
  }

  public async getSubscriptions(getWebhooksData: GetWebhooksData) {
    const { cursor, limit, status } = getWebhooksData;

    const where: { status?: WebhookSubscriptionStatus } = {};
    if (status) where.status = status;

    const result = await paginateWithCursor(
      args =>
        prisma.webhookSubscription.findMany({
          where,
          orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
          select: {
            id: true,
            name: true,
            url: true,
            description: true,
            status: true,
            events: true,
            failureCount: true,
            lastDeliveryAt: true,
            lastSuccessAt: true,
            disabledAt: true,
            disabledReason: true,
            createdAt: true,
            updatedAt: true,
          },
          ...args,
        }),
      () => prisma.webhookSubscription.count({ where }),
      { cursor, limit }
    );

    return {
      subscriptions: result.data,
      pagination: result.pagination,
    };
  }

  public async getSubscriptionById(getWebhookByIdData: GetWebhookByIdData) {
    const { id } = getWebhookByIdData;

    const subscription = await prisma.webhookSubscription.findUnique({
      where: { id },
      select: {
        id: true,
        name: true,
        url: true,
        description: true,
        status: true,
        events: true,
        failureCount: true,
        lastDeliveryAt: true,
        lastSuccessAt: true,
        disabledAt: true,
        disabledReason: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    if (!subscription) {
      throw new AppError('Webhook subscription not found', HTTPSTATUS.NOT_FOUND);
    }

    return subscription;
  }

  public async updateSubscription(updateWebhookSubscriptionInput: UpdateWebhookSubscriptionInput) {
    const { id, data } = updateWebhookSubscriptionInput;

    const existing = await prisma.webhookSubscription.findUnique({
      where: { id },
    });

    if (!existing) {
      throw new AppError('Webhook subscription not found', HTTPSTATUS.NOT_FOUND);
    }

    if (data.url) {
      await validateWebhookUrl(data.url);
    }

    if (data.events) {
      for (const eventType of data.events) {
        if (!isValidEventType(eventType)) {
          throw new AppError(
            `Invalid or unsupported event type: ${eventType}`,
            HTTPSTATUS.BAD_REQUEST
          );
        }
      }
    }

    const updated = await prisma.webhookSubscription.update({
      where: { id },
      data: {
        name: data.name ?? existing.name,
        url: data.url ?? existing.url,
        description: data.description ?? existing.description,
        events: data.events ?? existing.events,
        status: data.status ?? existing.status,
      },
      select: {
        id: true,
        name: true,
        url: true,
        description: true,
        status: true,
        events: true,
        failureCount: true,
        lastDeliveryAt: true,
        lastSuccessAt: true,
        disabledAt: true,
        disabledReason: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    return updated;
  }

  public async deleteSubscription(deleteWebhookSubscriptionData: DeleteWebhookSubscriptionData) {
    const { id } = deleteWebhookSubscriptionData;

    const existing = await prisma.webhookSubscription.findUnique({
      where: { id },
    });

    if (!existing) {
      throw new AppError('Webhook subscription not found', HTTPSTATUS.NOT_FOUND);
    }

    await prisma.$transaction([
      prisma.webhookDelivery.deleteMany({
        where: { webhookSubscriptionId: id },
      }),
      prisma.webhookSubscription.delete({
        where: { id },
      }),
    ]);

    return { success: true };
  }

  public async rotateSecret(rotateWebhookSecretData: RotateWebhookSecretData) {
    const { id } = rotateWebhookSecretData;

    const existing = await prisma.webhookSubscription.findUnique({
      where: { id },
    });

    if (!existing) {
      throw new AppError('Webhook subscription not found', HTTPSTATUS.NOT_FOUND);
    }

    const newSecret = generateSigningSecret();
    const previousSecretExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours grace

    const updated = await prisma.webhookSubscription.update({
      where: { id },
      data: {
        secret: newSecret,
        previousSecret: existing.secret,
        previousSecretExpiresAt,
      },
    });

    return {
      id: updated.id,
      secret: newSecret,
      previousSecretExpiresAt,
    };
  }

  public async dispatchDomainEvent(
    dispatchDomainEventData: DispatchDomainEventData
  ): Promise<number> {
    const { envelope } = dispatchDomainEventData;

    // Find active subscriptions that match the event type or wildcard '*'
    const subscriptions = await prisma.webhookSubscription.findMany({
      where: {
        status: WebhookSubscriptionStatus.ACTIVE,
        OR: [{ events: { has: envelope.type } }, { events: { has: '*' } }],
      },
    });

    if (subscriptions.length === 0) return 0;

    for (const sub of subscriptions) {
      const delivery = await prisma.webhookDelivery.create({
        data: {
          webhookSubscriptionId: sub.id,
          eventId: envelope.id,
          eventType: envelope.type,
          eventVersion: envelope.version,
          status: WebhookDeliveryStatus.PENDING,
          requestTimestamp: new Date(),
          requestPayload: envelope as unknown as object,
        },
      });

      // Attempt immediate delivery asynchronously
      setImmediate(() => {
        this.processDeliveryAttempt({ deliveryId: delivery.id }).catch(() => {});
      });
    }

    return subscriptions.length;
  }

  public async processDeliveryAttempt(processDeliveryAttemptData: ProcessDeliveryAttemptData) {
    const { deliveryId } = processDeliveryAttemptData;

    const delivery = await prisma.webhookDelivery.findUnique({
      where: { id: deliveryId },
      include: { subscription: true },
    });

    if (!delivery || !delivery.subscription) return;
    if (delivery.subscription.status !== WebhookSubscriptionStatus.ACTIVE) return;

    const envelope = delivery.requestPayload as unknown as WebhookEventEnvelope;
    const attempt = delivery.attemptNumber ?? 1;

    const result = await executeDeliveryHttp({
      url: delivery.subscription.url,
      secret: delivery.subscription.secret,
      previousSecret: delivery.subscription.previousSecret,
      previousSecretExpiresAt: delivery.subscription.previousSecretExpiresAt,
      envelope,
    });

    const now = new Date();

    if (result.success) {
      await prisma.$transaction([
        prisma.webhookDelivery.update({
          where: { id: delivery.id },
          data: {
            status: WebhookDeliveryStatus.SUCCESS,
            httpStatus: result.httpStatus,
            responseTimestamp: now,
            duration: result.duration,
            responseBody: result.responseBody,
          },
        }),
        prisma.webhookSubscription.update({
          where: { id: delivery.subscription.id },
          data: {
            lastDeliveryAt: now,
            lastSuccessAt: now,
            failureCount: 0,
          },
        }),
      ]);
      return;
    }

    // Determine if error is transient (retryable)
    const isTransient =
      !result.httpStatus ||
      result.httpStatus === 408 ||
      result.httpStatus === 429 ||
      result.httpStatus >= 500;

    const newFailureCount = delivery.subscription.failureCount + 1;
    const shouldDisable = newFailureCount >= 10;

    if (isTransient && attempt < MAX_WEBHOOK_RETRIES) {
      const delayMs = calculateBackoffDelayMs(attempt);
      const nextRetryAt = new Date(Date.now() + delayMs);

      await prisma.$transaction([
        prisma.webhookDelivery.update({
          where: { id: delivery.id },
          data: {
            status: WebhookDeliveryStatus.PENDING,
            attemptNumber: attempt + 1,
            httpStatus: result.httpStatus ?? null,
            responseTimestamp: now,
            duration: result.duration,
            errorCode: result.errorCode,
            errorMessage: result.errorMessage,
            responseBody: result.responseBody,
            nextRetryAt,
          },
        }),
        prisma.webhookSubscription.update({
          where: { id: delivery.subscription.id },
          data: {
            lastDeliveryAt: now,
            failureCount: newFailureCount,
            status: shouldDisable
              ? WebhookSubscriptionStatus.DISABLED
              : delivery.subscription.status,
            disabledAt: shouldDisable ? now : delivery.subscription.disabledAt,
            disabledReason: shouldDisable
              ? 'Automatically disabled due to 10 consecutive delivery failures'
              : delivery.subscription.disabledReason,
          },
        }),
      ]);
      return;
    }

    // Permanent 4xx failure or retries exceeded
    const finalStatus =
      attempt >= MAX_WEBHOOK_RETRIES
        ? WebhookDeliveryStatus.RETRIES_EXCEEDED
        : WebhookDeliveryStatus.FAILURE;

    await prisma.$transaction([
      prisma.webhookDelivery.update({
        where: { id: delivery.id },
        data: {
          status: finalStatus,
          httpStatus: result.httpStatus ?? null,
          responseTimestamp: now,
          duration: result.duration,
          errorCode: result.errorCode,
          errorMessage: result.errorMessage,
          responseBody: result.responseBody,
        },
      }),
      prisma.webhookSubscription.update({
        where: { id: delivery.subscription.id },
        data: {
          lastDeliveryAt: now,
          failureCount: newFailureCount,
          status: shouldDisable ? WebhookSubscriptionStatus.DISABLED : delivery.subscription.status,
          disabledAt: shouldDisable ? now : delivery.subscription.disabledAt,
          disabledReason: shouldDisable
            ? 'Automatically disabled due to 10 consecutive delivery failures'
            : delivery.subscription.disabledReason,
        },
      }),
    ]);
  }

  public async testWebhook(testWebhookData: TestWebhookData) {
    const { id } = testWebhookData;

    const subscription = await prisma.webhookSubscription.findUnique({
      where: { id },
    });

    if (!subscription) {
      throw new AppError('Webhook subscription not found', HTTPSTATUS.NOT_FOUND);
    }

    const testEnvelope = buildEventEnvelope('webhook.test', {
      message: 'This is a test webhook payload sent from AuthKit platform.',
      subscriptionId: subscription.id,
      timestamp: new Date().toISOString(),
    });

    const delivery = await prisma.webhookDelivery.create({
      data: {
        webhookSubscriptionId: subscription.id,
        eventId: testEnvelope.id,
        eventType: testEnvelope.type,
        eventVersion: testEnvelope.version,
        status: WebhookDeliveryStatus.PENDING,
        requestTimestamp: new Date(),
        requestPayload: testEnvelope as unknown as object,
        isTest: true,
      },
    });

    await this.processDeliveryAttempt({ deliveryId: delivery.id });

    return prisma.webhookDelivery.findUnique({
      where: { id: delivery.id },
    });
  }

  public async getDeliveries(getDeliveriesInputData: GetDeliveriesInputData) {
    const { subscriptionId, params } = getDeliveriesInputData;

    const subscription = await prisma.webhookSubscription.findUnique({
      where: { id: subscriptionId },
    });

    if (!subscription) {
      throw new AppError('Webhook subscription not found', HTTPSTATUS.NOT_FOUND);
    }

    const { cursor, limit, status } = params;

    const where: { webhookSubscriptionId: string; status?: WebhookDeliveryStatus } = {
      webhookSubscriptionId: subscriptionId,
    };
    if (status) where.status = status;

    const result = await paginateWithCursor(
      args =>
        prisma.webhookDelivery.findMany({
          where,
          orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
          ...args,
        }),
      () => prisma.webhookDelivery.count({ where }),
      { cursor, limit }
    );

    return {
      deliveries: result.data,
      pagination: result.pagination,
    };
  }

  public async getDeliveryById(getDeliveryByIdData: GetDeliveryByIdData) {
    const { subscriptionId, deliveryId } = getDeliveryByIdData;

    const subscription = await prisma.webhookSubscription.findUnique({
      where: { id: subscriptionId },
    });

    if (!subscription) {
      throw new AppError('Webhook subscription not found', HTTPSTATUS.NOT_FOUND);
    }

    const delivery = await prisma.webhookDelivery.findFirst({
      where: {
        id: deliveryId,
        webhookSubscriptionId: subscriptionId,
      },
    });

    if (!delivery) {
      throw new AppError('Webhook delivery record not found', HTTPSTATUS.NOT_FOUND);
    }

    return delivery;
  }
}
