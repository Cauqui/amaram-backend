// config/db.js o db.js
const { Pool } = require('pg');
require('dotenv').config(); 

// Inicialización del Pool de conexiones relacionales optimizadas
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  max: 20, // 🛡️ Disponibilidad: Límite máximo de conexiones concurrentes para mitigar ataques de denegación de servicio (DoS)
  idleTimeoutMillis: 30000, // Cierra conexiones inactivas automáticamente para liberar memoria del servidor
  connectionTimeoutMillis: 2000, // Tiempo límite de espera para evitar hilos colgados
});

// 🛡️ OWASP A09:2025 - Registro de Eventos de Auditoría de Infraestructura
pool.on('connect', () => {
  // Se dispara de manera asíncrona solo la primera vez que se establece un canal seguro con la base de datos
  console.log(`📡 [INFRASTRUCTURE] [${new Date().toISOString()}] - Conexión de datos enrutada con éxito a PostgreSQL: ${process.env.DB_NAME}`);
});

// 🛡️ OWASP A10:2025 - Interceptor Global de Condiciones Excepcionales en Red Relacional
pool.on('error', (err, client) => {
  console.error(`\n🚨 [DATABASE EXCEPTION] [${new Date().toISOString()}] - Pérdida de conectividad o fallo en el pool activo.`);
  console.error(`Detalle técnico del error: ${err.message}\n`);
  // Evita que Express colapse de forma imprevista ante una caída del motor de persistencia, preservando la resiliencia del sistema
});

// Exportación segura del pool para la ejecución de consultas estrictamente parametrizadas (Anti-SQLi)
module.exports = pool;