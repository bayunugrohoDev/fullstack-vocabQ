#!/bin/bash

# Define the base directory for schema files
SCHEMA_DIR="src/db/schema"

# Create schema directory if it doesn't exist
mkdir -p "$SCHEMA_DIR"

echo "Creating schema files in $SCHEMA_DIR..."

# --- languages.ts ---
cat <<EOL > "$SCHEMA_DIR/languages.ts"
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
EOL
echo "Created $SCHEMA_DIR/languages.ts"

# --- users.ts ---
cat <<EOL > "$SCHEMA_DIR/users.ts"
import { pgTable, uuid, varchar, timestamp } from 'drizzle-orm/pg-core';
import { relations } => 'drizzle-orm';
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
EOL
echo "Created $SCHEMA_DIR/users.ts"

# --- vocabEntries.ts ---
cat <<EOL > "$SCHEMA_DIR/vocabEntries.ts"
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
EOL
echo "Created $SCHEMA_DIR/vocabEntries.ts"

# --- userVocabProgress.ts ---
cat <<EOL > "$SCHEMA_DIR/userVocabProgress.ts"
import { pgTable, uuid, integer, timestamp, boolean, primaryKey } from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
import { users } from './users'; // Impor users
import { vocabEntries } from './vocabEntries'; // Impor vocabEntries

export const userVocabProgress = pgTable('user_vocab_progress', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  vocabEntryId: uuid('vocab_entry_id').notNull().references(() => vocabEntries.id, { onDelete: 'cascade' }),
  masteryScore: integer('mastery_score').default(0).notNull(),
  reviewedAt: timestamp('reviewed_at').notNull(),
  isKnown: boolean('is_known').default(false).notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
}, (table) => {
  return {
    unqUserVocab: primaryKey(table.userId, table.vocabEntryId),
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
EOL
echo "Created $SCHEMA_DIR/userVocabProgress.ts"

# --- categories.ts ---
cat <<EOL > "$SCHEMA_DIR/categories.ts"
import { pgTable, uuid, varchar, timestamp } from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
import { users } from './users'; // Impor users
import { vocabCategories } from './vocabCategories'; // Impor vocabCategories

export const categories = pgTable('categories', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  name: varchar('name', { length: 255 }).notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
});

export const categoriesRelations = relations(categories, ({ one, many }) => ({
  user: one(users, {
    fields: [categories.userId],
    references: [users.id],
  }),
  vocabCategories: many(vocabCategories),
}));
EOL
echo "Created $SCHEMA_DIR/categories.ts"

# --- vocabCategories.ts ---
cat <<EOL > "$SCHEMA_DIR/vocabCategories.ts"
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
EOL
echo "Created $SCHEMA_DIR/vocabCategories.ts"

# --- index.ts (in schema directory) ---
cat <<EOL > "$SCHEMA_DIR/index.ts"
// src/db/schema/index.ts
export * from './users';
export * from './languages';
export * from './vocabEntries';
export * from './userVocabProgress';
export * from './categories';
export * from './vocabCategories';
EOL
echo "Created/Updated $SCHEMA_DIR/index.ts"

# --- Update src/db/index.ts ---
# Ensure the main db connection file uses the new schema structure
cat <<EOL > "src/db/index.ts"
import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';
import * as schema from './schema'; // Mengimpor semua schema dari file index.ts di folder schema
import * as dotenv from 'dotenv';

dotenv.config({ path: '.env.local' });

if (!process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL is not set');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

export const db = drizzle(pool, { schema });
EOL
echo "Updated src/db/index.ts"

echo "Schema file creation complete."
echo "Don't forget to run 'npm run db:generate' and 'npm run db:migrate' to apply changes to your database."