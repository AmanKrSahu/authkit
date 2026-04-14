import { AppError } from '@core/common/utils/app-error';
import { comparePassword } from '@core/common/utils/bcrypt';
import { logger } from '@core/common/utils/logger';
import { config } from '@core/config/app.config';
import { HTTPSTATUS } from '@core/config/http.config';
import { oidcConfig } from '@core/config/oidc.config';
import prisma from '@core/database/prisma';
import type { Request, Response } from 'express';
import Provider, { type ClientMetadata } from 'oidc-provider';

interface ConsentDetail {
  scopes?: {
    new: string[];
    accepted?: string[];
    rejected?: string[];
  };
  missingOIDCScope?: string[];
}

export class OidcService {
  private provider: Provider;

  constructor() {
    const protocol = config.NODE_ENV === 'production' ? 'https' : 'http';
    const port = config.NODE_ENV === 'production' ? '' : `:${config.PORT}`;
    const issuer = `${protocol}://${config.DOMAIN_URL}${port}${config.BASE_PATH}/oidc`;

    this.provider = new Provider(issuer, oidcConfig);
    this.provider.proxy = true;

    this.provider.Client.find = async (id: string) => {
      const client = await prisma.oidcClient.findUnique({
        where: { clientId: id },
      });

      if (!client) return;

      return new (this.provider.Client as new (
        metadata: ClientMetadata
      ) => InstanceType<Provider['Client']>)({
        client_id: client.clientId,
        client_secret: client.clientSecret,
        redirect_uris: client.redirectUrls,
        grant_types: client.grantTypes,
        scope: client.scope ?? undefined,
      });
    };

    this.provider.Client.prototype.compareClientSecret = async function (secret: string) {
      if (!this.clientSecret) return false;

      return comparePassword(secret, this.clientSecret);
    };
  }

  public getProvider(): Provider {
    return this.provider;
  }

  public async getInteractionContext(req: Request, res: Response) {
    try {
      const details = await this.provider.interactionDetails(req, res);
      const client = await this.provider.Client.find(details.params.client_id as string);

      return {
        details,
        client,
      };
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError('Failed to get interaction context', HTTPSTATUS.INTERNAL_SERVER_ERROR);
    }
  }

  public async submitLogin(req: Request, res: Response, accountId: string) {
    try {
      const result = {
        login: {
          accountId,
        },
      };

      await this.provider.interactionFinished(req, res, result, {
        mergeWithLastSubmission: false,
      });
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError('Failed to submit login interaction', HTTPSTATUS.INTERNAL_SERVER_ERROR);
    }
  }

  public async submitConsent(req: Request, res: Response) {
    try {
      const interactionDetails = await this.provider.interactionDetails(req, res);
      const {
        prompt: { name, details },
        params,
        session,
      } = interactionDetails;

      if (name !== 'consent') {
        throw new AppError('Unexpected interaction for confirmation', HTTPSTATUS.BAD_REQUEST);
      }

      const grant = new this.provider.Grant({
        accountId: session?.accountId,
        clientId: params.client_id as string,
      });

      const detailsScopes = (details as ConsentDetail).scopes;
      const missingOIDCScope = (details as ConsentDetail).missingOIDCScope;

      if (detailsScopes?.new?.find((s: string) => s === 'openid')) {
        grant.addOIDCScope('openid');
      }

      if (missingOIDCScope?.find((s: string) => s === 'openid')) {
        grant.addOIDCScope('openid');
      }

      if (params.scope) {
        const scopes = (params.scope as string).split(' ');
        scopes.forEach(s => grant.addOIDCScope(s));
      }

      const grantId = await grant.save();

      const result = { consent: { grantId } };

      await this.provider.interactionFinished(req, res, result, {
        mergeWithLastSubmission: true,
      });
    } catch (error) {
      logger.error('Error submitting OIDC consent interaction:', error);
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError('Failed to submit consent interaction', HTTPSTATUS.INTERNAL_SERVER_ERROR);
    }
  }

  public async abortSession(req: Request, res: Response) {
    try {
      const result = {
        error: 'access_denied',
        error_description: 'End-User aborted interaction',
      };

      await this.provider.interactionFinished(req, res, result, {
        mergeWithLastSubmission: false,
      });
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError('Failed to abort interaction', HTTPSTATUS.INTERNAL_SERVER_ERROR);
    }
  }
}
