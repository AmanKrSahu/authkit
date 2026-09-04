import {
  createWebhookSubscriptionSchema,
  updateWebhookSubscriptionSchema,
} from '@core/common/validators/webhook.validator';
import { HTTPSTATUS } from '@core/config/http.config';
import { AsyncHandler } from '@core/decorator/async-handler.decorator';
import { WebhookDeliveryStatus, WebhookSubscriptionStatus } from '@prisma/client';
import type { Request, Response } from 'express';

import { WebhookService } from '../services/webhook.service';

export class WebhookController {
  private webhookService: WebhookService;

  constructor(webhookService: WebhookService = new WebhookService()) {
    this.webhookService = webhookService;
  }

  @AsyncHandler
  public createSubscription = async (req: Request, res: Response) => {
    const validatedData = createWebhookSubscriptionSchema.parse(req.body);
    const createdBy = (req.user as { userId?: string })?.userId;

    const subscription = await this.webhookService.createSubscription({
      ...validatedData,
      createdBy,
    });

    return res.status(HTTPSTATUS.CREATED).json({
      success: true,
      message: 'Webhook subscription created successfully',
      data: { subscription },
    });
  };

  @AsyncHandler
  public getSubscriptions = async (req: Request, res: Response) => {
    const cursor = req.query.cursor as string | undefined;
    const limit = req.query.limit ? Number.parseInt(req.query.limit as string, 10) : undefined;
    const status = req.query.status as WebhookSubscriptionStatus | undefined;

    const { subscriptions, pagination } = await this.webhookService.getSubscriptions({
      cursor,
      limit,
      status,
    });

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'Webhook subscriptions retrieved successfully',
      data: { subscriptions, pagination },
    });
  };

  @AsyncHandler
  public getSubscriptionById = async (req: Request, res: Response) => {
    const id = req.params.id as string;
    const subscription = await this.webhookService.getSubscriptionById({ id });

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'Webhook subscription details retrieved successfully',
      data: { subscription },
    });
  };

  @AsyncHandler
  public updateSubscription = async (req: Request, res: Response) => {
    const id = req.params.id as string;
    const validatedData = updateWebhookSubscriptionSchema.parse(req.body);

    const subscription = await this.webhookService.updateSubscription({
      id,
      data: validatedData,
    });

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'Webhook subscription updated successfully',
      data: { subscription },
    });
  };

  @AsyncHandler
  public deleteSubscription = async (req: Request, res: Response) => {
    const id = req.params.id as string;
    await this.webhookService.deleteSubscription({ id });

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'Webhook subscription deleted successfully',
    });
  };

  @AsyncHandler
  public rotateSecret = async (req: Request, res: Response) => {
    const id = req.params.id as string;
    const rotationResult = await this.webhookService.rotateSecret({ id });

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'Webhook signing secret rotated successfully',
      data: { rotation: rotationResult },
    });
  };

  @AsyncHandler
  public testWebhook = async (req: Request, res: Response) => {
    const id = req.params.id as string;
    const delivery = await this.webhookService.testWebhook({ id });

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'Test webhook event dispatched successfully',
      data: { delivery },
    });
  };

  @AsyncHandler
  public getDeliveries = async (req: Request, res: Response) => {
    const id = req.params.id as string;
    const cursor = req.query.cursor as string | undefined;
    const limit = req.query.limit ? Number.parseInt(req.query.limit as string, 10) : undefined;
    const status = req.query.status as WebhookDeliveryStatus | undefined;

    const { deliveries, pagination } = await this.webhookService.getDeliveries({
      subscriptionId: id,
      params: {
        cursor,
        limit,
        status,
      },
    });

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'Webhook deliveries retrieved successfully',
      data: { deliveries, pagination },
    });
  };

  @AsyncHandler
  public getDeliveryById = async (req: Request, res: Response) => {
    const id = req.params.id as string;
    const deliveryId = req.params.deliveryId as string;
    const delivery = await this.webhookService.getDeliveryById({
      subscriptionId: id,
      deliveryId,
    });

    return res.status(HTTPSTATUS.OK).json({
      success: true,
      message: 'Webhook delivery details retrieved successfully',
      data: { delivery },
    });
  };
}
