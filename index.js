// index.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet'); // 🛡️ OWASP A02:2025 - Cabeceras HTTP seguras perimetrales

const app = express();
// 🛡️ OWASP A05:2025 - Habilitar confianza en el proxy perimetral de Render para express-rate-limit
app.set('trust proxy', 1);
const port = process.env.PORT || 3000;

// Middlewares globales de procesamiento y seguridad
app.use(helmet()); // 🛡️ Mitiga ataques de inyección perimetral (XSS, Clickjacking, MIME sniffing)
app.use(cors());
app.use(express.json());

// Importación de Enrutadores Modulares
const productosRoutes = require('./routes/productos.routes.js');
const usuariosRoutes = require('./routes/usuarios.routes.js');
const clientesRoutes = require('./routes/clientes.routes.js');
const authRoutes = require('./routes/auth.routes.js');
const categoriasRoutes = require('./routes/categorias.routes.js');
const ventasRoutes = require('./routes/ventas.routes.js'); 
// 🛡️ OWASP A09:2025 - Importación del Enrutador Forense de Auditoría
const auditoriaRoutes = require('./routes/auditoria.routes.js');

// Activación de Rutas Base del Backend
app.use('/api/productos', productosRoutes);
app.use('/api/usuarios', usuariosRoutes);
app.use('/api/clientes', clientesRoutes);
app.use('/api', authRoutes);
app.use('/api/categorias', categoriasRoutes);
app.use('/api/ventas', ventasRoutes); 
// 🛡️ OWASP A01:2025 - Activación de la ruta para el Core Administrativo
app.use('/api/auditoria', auditoriaRoutes);

// Ruta de Control de Salud de la Base de Datos (Mapeada de manera segura)
const pool = require('./config/db');
app.get('/api/prueba', async (req, res) => {
  try {
    const result = await pool.query('SELECT 1 as test');
    res.json({ 
      status: "success", 
      mensaje: "Conexión a la base de datos PostgreSQL establecida con éxito", 
      data: result.rows[0] 
    });
  } catch (error) {
    console.error(`[DATABASE-ERROR] [${new Date().toISOString()}] - Fallo crítico: ${error.message}`);
    res.status(500).json({ 
      status: "error", 
      mensaje: "Error interno de comunicación con los servicios relacionales" 
    });
  }
});

// 🛡️ OWASP A10:2025 - INTERCEPTOR GLOBAL DE CONDICIONES EXCEPCIONALES (MANEJO DE ERRORES)
app.use((err, req, res, next) => {
  console.error(`\n🚨 [SERVER EXCEPTION] [${new Date().toISOString()}]`);
  console.error(`Ruta del fallo: ${req.method} ${req.originalUrl}`);
  console.error(`Pila de llamadas técnica:\n${err.stack}\n`);

  res.status(500).json({
    status: "error",
    mensaje: "Ocurrió un error inesperado al procesar la solicitud en el servidor seguro."
  });
});

// Inicio del servidor
app.listen(port, () => console.log(`✅ Servidor AMARAM en http://localhost:${port}`));