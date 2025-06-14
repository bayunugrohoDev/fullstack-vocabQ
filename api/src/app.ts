import express from 'express';
import routes from './routes'; // Import semua route Anda

const app = express();

app.use(express.json()); // Middleware untuk parsing body JSON

// Route utama API
app.use('/api', routes); // Semua route API Anda akan diawali dengan /api

// Contoh route dasar
app.get('/', (req, res) => {
  res.send('Welcome to the Node.js API with Express, PostgreSQL, TypeScript, and Drizzle!');
});

export default app;
