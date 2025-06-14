import { defineConfig } from 'drizzle-kit';

export default defineConfig({
  out: './drizzle',
//   schema: [
//     './src/db/productsSchema.ts',
//     './src/db/usersSchema.ts',
//     './src/db/ordersSchema.ts',
//   ],
  schema: './src/db/schema/index.ts',
  dialect: 'postgresql',
  dbCredentials: {
    url: process.env.DATABASE_URL!,
  },
  verbose: true,
  strict: true,
});
