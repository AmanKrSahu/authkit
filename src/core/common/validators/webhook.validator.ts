import { z } from 'zod';

import { isValidEventType } from '../../events/event-catalog';

export const createWebhookSubscriptionSchema = z.object({
  name: z.string().min(1, 'Name is required').max(100, 'Name must be 100 characters or less'),
  url: z.string().url('Invalid webhook URL format'),
  description: z.string().max(500, 'Description must be 500 characters or less').optional(),
  events: z
    .array(z.string())
    .min(1, 'At least one event type or wildcard "*" is required')
    .refine(events => events.every(e => isValidEventType(e)), {
      message: 'One or more event types are not present in the Shared Event Catalog',
    }),
});

export const updateWebhookSubscriptionSchema = z.object({
  name: z.string().min(1).max(100).optional(),
  url: z.string().url('Invalid webhook URL format').optional(),
  description: z.string().max(500).optional(),
  events: z
    .array(z.string())
    .min(1)
    .refine(events => events.every(e => isValidEventType(e)), {
      message: 'One or more event types are not present in the Shared Event Catalog',
    })
    .optional(),
  status: z.enum(['ACTIVE', 'PAUSED', 'DISABLED']).optional(),
});
