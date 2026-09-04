import type { WebhookDeliveryStatus, WebhookSubscriptionStatus } from '@prisma/client';

import type { WebhookEventEnvelope } from '../../events/event-catalog';

export interface CreateWebhookSubscriptionData {
  name: string;
  url: string;
  description?: string;
  events: string[];
  createdBy?: string;
}

export interface GetWebhooksData {
  cursor?: string;
  limit?: number;
  status?: WebhookSubscriptionStatus;
}

export interface GetWebhookByIdData {
  id: string;
}

export interface UpdateWebhookSubscriptionData {
  name?: string;
  url?: string;
  description?: string;
  events?: string[];
  status?: WebhookSubscriptionStatus;
}

export interface UpdateWebhookSubscriptionInput {
  id: string;
  data: UpdateWebhookSubscriptionData;
}

export interface DeleteWebhookSubscriptionData {
  id: string;
}

export interface RotateWebhookSecretData {
  id: string;
}

export interface TestWebhookData {
  id: string;
}

export interface GetDeliveriesData {
  cursor?: string;
  limit?: number;
  status?: WebhookDeliveryStatus;
}

export interface GetDeliveriesInputData {
  subscriptionId: string;
  params: GetDeliveriesData;
}

export interface GetDeliveryByIdData {
  subscriptionId: string;
  deliveryId: string;
}

export interface ProcessDeliveryAttemptData {
  deliveryId: string;
}

export interface DispatchDomainEventData {
  envelope: WebhookEventEnvelope;
}

export interface ExecuteDeliveryHttpParams {
  url: string;
  secret: string;
  previousSecret?: string | null;
  previousSecretExpiresAt?: Date | null;
  envelope: WebhookEventEnvelope;
}

export interface WebhookDeliveryAttemptResult {
  success: boolean;
  httpStatus?: number;
  duration: number;
  errorCode?: string;
  errorMessage?: string;
  responseBody?: string;
}
