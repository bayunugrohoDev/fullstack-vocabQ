// src/db/seed/index.ts
import { seedLanguages } from './languages.seed'; // Impor seed bahasa

async function runSeed() {
  console.log('✨ Running database seed scripts...');
  try {
    // Jalankan setiap seed function secara berurutan
    await seedLanguages();
    // Tambahkan pemanggilan seed function lain di sini jika Anda memiliki lebih banyak tabel:
    // await seedCategories();
    // await seedInitialUsers();

    console.log('✅ All seed scripts executed successfully!');
    process.exit(0); // Berhasil
  } catch (error) {
    console.error('❌ Database seeding failed!');
    console.error(error);
    process.exit(1); // Gagal
  }
}

// Jalankan fungsi seed
runSeed();