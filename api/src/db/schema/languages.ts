import { pgTable, uuid, varchar, timestamp } from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
import { users } from './users'; // Impor users jika diperlukan relasi balik

export const languages = pgTable('languages', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: varchar('name', { length: 255 }).notNull(),
  code: varchar('code', { length: 10 }).unique().notNull(), // e.g., 'id', 'ar', 'en'
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
});

export const languagesRelations = relations(languages, ({ many }) => ({
  users: many(users), // Satu bahasa bisa dimiliki oleh banyak user (sebagai current_language)
  // vocabEntries: many(vocabEntries), // Akan ditambahkan di vocabEntries.ts jika Anda ingin menghubungkan
}));
