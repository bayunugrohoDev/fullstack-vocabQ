// src/db/seed/languages.seed.ts
import { db } from '../index'; // Sesuaikan path jika db Anda ada di lokasi lain (src/db/index.ts)
import { languages } from '../schema/languages'; // Sesuaikan path ke file schema languages Anda
import { InferInsertModel } from 'drizzle-orm';

// Definisikan tipe untuk data bahasa yang akan di-seed
type NewLanguage = InferInsertModel<typeof languages>;

// 20 Bahasa Populer
const languagesToSeed: NewLanguage[] = [
  { name: 'English', code: 'en' },
  { name: 'Mandarin Chinese', code: 'zh' },
  { name: 'Spanish', code: 'es' },
  { name: 'Hindi', code: 'hi' },
  { name: 'French', code: 'fr' },
  { name: 'Standard Arabic', code: 'ar' },
  { name: 'Bengali', code: 'bn' },
  { name: 'Russian', code: 'ru' },
  { name: 'Portuguese', code: 'pt' },
  { name: 'Urdu', code: 'ur' },
  { name: 'Indonesian', code: 'id' },
  { name: 'German', code: 'de' },
  { name: 'Japanese', code: 'ja' },
  { name: 'Punjabi', code: 'pa' },
  { name: 'Marathi', code: 'mr' },
  { name: 'Telugu', code: 'te' },
  { name: 'Turkish', code: 'tr' },
  { name: 'Korean', code: 'ko' },
  { name: 'Vietnamese', code: 'vi' },
  { name: 'Italian', code: 'it' },
];

export async function seedLanguages() {
  console.log('--- Starting language seeding ---');
  try {
    let insertedCount = 0;
    for (const lang of languagesToSeed) {
      // Menggunakan onConflictDoNothing agar tidak error jika kode bahasa sudah ada
      const result = await db.insert(languages)
        .values({
          name: lang.name,
          code: lang.code,
        })
        .onConflictDoNothing({
          target: languages.code, // Menggunakan kolom 'code' sebagai target konflik unik
        })
        .returning({ id: languages.id }); // Minta ID yang disisipkan (jika ada)

      if (result.length > 0) {
        insertedCount++;
        console.log(`✅ Seeded language: ${lang.name} (${lang.code})`);
      } else {
        console.log(`⏭️ Skipped existing language: ${lang.name} (${lang.code})`);
      }
    }
    console.log(`--- Language seeding finished. Total new languages inserted: ${insertedCount} ---`);
  } catch (error) {
    console.error('❌ Error seeding languages:', error);
    throw error; // Lempar error agar bisa ditangkap oleh fungsi utama
  }
}