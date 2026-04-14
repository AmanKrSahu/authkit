import crypto from 'node:crypto';
import fs from 'node:fs/promises';

import { exportJWK, generateKeyPair } from 'jose';

async function generate() {
  // eslint-disable-next-line unicorn/consistent-function-scoping
  const generateSecret = () => crypto.randomBytes(32).toString('hex');

  const secrets = {
    JWT_SECRET: generateSecret(),
    JWT_REFRESH_SECRET: generateSecret(),
    JWT_RESET_SECRET: generateSecret(),
    JWT_MFA_LOGIN_SECRET: generateSecret(),
    AUTHENTICATOR_APP_SECRET: generateSecret(),
    OIDC_COOKIE_KEYS: generateSecret(),
  };

  const { privateKey } = await generateKeyPair('RS256', { extractable: true });
  const jwk = await exportJWK(privateKey);

  jwk.kid = 'dev-key-1';
  jwk.use = 'sig';

  // Output as a JWKS structure { keys: [jwk] } to be directly usable in env vars
  const jwks = { keys: [jwk] };

  const output = {
    ...secrets,
    OIDC_JWKS: JSON.stringify(jwks),
  };

  await fs.writeFile('generated-secrets.json', JSON.stringify(output, null, 2));

  // eslint-disable-next-line no-console
  console.log('Secrets and JWKS saved to generated-secrets.json');
}

await generate();
