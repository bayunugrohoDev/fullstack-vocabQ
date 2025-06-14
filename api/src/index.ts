import express, { json, urlencoded, Request } from 'express';
// import productsRoutes from './routes/products/index.js';
// import authRoutes from './routes/auth/index.js';
// import ordersRoutes from './routes/orders/index.js';
// import stripeRoutes from './routes/stripe/index.js';
import routes from './routes'; // Import semua route Anda

import serverless from 'serverless-http';

const port = 3001;
const app = express();

app.use(urlencoded({ extended: false }));
// app.use(
//   json({
//     verify: (req: Request, res, buf) => {
//       req.rawBody = buf;
//     },
//   })
// );

app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.use(express.json()); // Middleware untuk parsing body JSON

// Route utama API
app.use('/api', routes); // Semua route API Anda akan diawali dengan /api

if (process.env.NODE_ENV === 'dev') {
  app.listen(port, () => {
    console.log(`Example app listening on port ${port}`);
  });
}

export const handler = serverless(app);
