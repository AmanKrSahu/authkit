import 'dotenv/config';

import { defineConfig } from 'prisma/config';

export default defineConfig({
  migrations: {
    seed: `tsx src/core/database/seed.ts`,
  },
});
