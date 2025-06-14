import { pgTable, uuid, timestamp, primaryKey } from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
import { vocabEntries } from './vocabEntries'; // Impor vocabEntries
import { categories } from './categories'; // Impor categories

export const vocabCategories = pgTable('vocab_categories', {
  vocabEntryId: uuid('vocab_entry_id').notNull().references(() => vocabEntries.id, { onDelete: 'cascade' }),
  categoryId: uuid('category_id').notNull().references(() => categories.id, { onDelete: 'cascade' }),
  createdAt: timestamp('created_at').defaultNow().notNull(),
}, (table) => {
  return {
    pk: primaryKey(table.vocabEntryId, table.categoryId),
  };
});

export const vocabCategoriesRelations = relations(vocabCategories, ({ one }) => ({
  vocabEntry: one(vocabEntries, {
    fields: [vocabCategories.vocabEntryId],
    references: [vocabEntries.id],
  }),
  category: one(categories, {
    fields: [vocabCategories.categoryId],
    references: [categories.id],
  }),
}));
