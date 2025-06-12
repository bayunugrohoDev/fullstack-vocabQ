import { pgTable, uuid, varchar, timestamp } from 'drizzle-orm/pg-core';
import { relations }from 'drizzle-orm';
import { languages } from './languages'; // Impor languages untuk relasi
import { categories } from './categories'; // Impor categories
import { userVocabProgress } from './userVocabProgress'; // Impor userVocabProgress
import { vocabEntries } from './vocabEntries'; // Impor vocabEntries (untuk created_by_user_id)

export const users = pgTable('users', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: varchar('name', { length: 255 }).notNull(),
  email: varchar('email', { length: 255 }).unique().notNull(),
  password: varchar('password', { length: 255 }).notNull(),
  currentLanguageId: uuid('current_language_id').references(() => languages.id, { onDelete: 'set null' }),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
});

export const usersRelations = relations(users, ({ one, many }) => ({
  currentLanguage: one(languages, {
    fields: [users.currentLanguageId],
    references: [languages.id],
  }),
  categories: many(categories), // Satu user bisa memiliki banyak kategori
  userVocabProgress: many(userVocabProgress), // Satu user bisa memiliki banyak progres vocabulary
  createdVocabEntries: many(vocabEntries), // Satu user bisa membuat banyak vocab entries
}));
