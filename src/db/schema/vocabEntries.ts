import { pgTable, uuid, text, timestamp } from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
import { languages } from './languages'; // Impor languages
import { users } from './users'; // Impor users
import { userVocabProgress } from './userVocabProgress'; // Impor userVocabProgress
import { vocabCategories } from './vocabCategories'; // Impor vocabCategories

export const vocabEntries = pgTable('vocab_entries', {
  id: uuid('id').primaryKey().defaultRandom(),
  originalWord: text('original_word').notNull(),
  meaning: text('meaning').notNull(),
  description: text('description'),
  exampleSentence: text('example_sentence'),
  languageId: uuid('language_id').notNull().references(() => languages.id, { onDelete: 'restrict' }),
  createdByUserId: uuid('created_by_user_id').references(() => users.id, { onDelete: 'set null' }),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
});

export const vocabEntriesRelations = relations(vocabEntries, ({ one, many }) => ({
  language: one(languages, {
    fields: [vocabEntries.languageId],
    references: [languages.id],
  }),
  createdBy: one(users, {
    fields: [vocabEntries.createdByUserId],
    references: [users.id],
  }),
  userVocabProgress: many(userVocabProgress),
  vocabCategories: many(vocabCategories),
}));
