import { pgTable, uuid, integer, timestamp, boolean, unique } from 'drizzle-orm/pg-core'; // <-- Perhatikan impor 'unique'
import { relations } from 'drizzle-orm';
import { users } from './users';
import { vocabEntries } from './vocabEntries';

export const userVocabProgress = pgTable('user_vocab_progress', {
  id: uuid('id').primaryKey().defaultRandom(), // Ini tetap PRIMARY KEY tunggal
  userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  vocabEntryId: uuid('vocab_entry_id').notNull().references(() => vocabEntries.id, { onDelete: 'cascade' }),
  masteryScore: integer('mastery_score').default(0).notNull(),
  reviewedAt: timestamp('reviewed_at').notNull(),
  isKnown: boolean('is_known').default(false).notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
}, (table) => {
  return {
    // Menggunakan unique constraint di sini, BUKAN primaryKey
    unqUserVocab: unique('user_vocab_unq').on(table.userId, table.vocabEntryId), // <-- Ubah primaryKey menjadi unique
  };
});

export const userVocabProgressRelations = relations(userVocabProgress, ({ one }) => ({
  user: one(users, {
    fields: [userVocabProgress.userId],
    references: [users.id],
  }),
  vocabEntry: one(vocabEntries, {
    fields: [userVocabProgress.vocabEntryId],
    references: [vocabEntries.id],
  }),
}));