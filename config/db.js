// config/db.js
const { Pool } = require('pg');
require('dotenv').config(); 

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  max: 20, 
  idleTimeoutMillis: 30000, 
  connectionTimeoutMillis: 2000, 
  // 🛡️ ENLACE SEGURO OBLIGATORIO PARA INFRAESTRUCTURAS EN LA NUBE (NEON / SUPABASE)
  ssl: {
    rejectUnauthorized: false // Permite establecer la conexión cifrada sin requerir certificados locales instalados
  }
});

pool.on('connect', () => {
  console.log(`📡 [INFRASTRUCTURE] [${new Date().toISOString()}] - Conexión de datos enrutada con éxito a PostgreSQL (SSL Activo): ${process.env.DB_NAME}`);
});

pool.on('error', (err, client) => {
  console.error(`\n🚨 [DATABASE EXCEPTION] [${new Date().toISOString()}] - Fallo en el pool activo.`);
  console.error(`Detalle técnico: ${err.message}\n`);
});

module.exports = pool;