// routes/productos.routes.js
const express = require('express');
const router = express.Router();
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

// Importamos el controlador y tu middleware de seguridad perimetral
const { obtenerProductos, crearProducto, actualizarProducto, eliminarProducto } = require('../controllers/producto.controller');
const { verificarToken } = require('../middleware');

// 🛡️ OWASP A05:2025 - Gestión Segura de Credenciales y Secretos de Terceros (Cloudinary)
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: { 
    folder: 'amaram_productos', 
    format: async () => 'jpg' 
  },
});
const upload = multer({ storage: storage });

// ============================================================================
// DEFINICIÓN DE RUTAS PERIMETRALES (Prefijo base: /api/productos)
// ============================================================================

// 🛒 Catálogo Público: Lectura sanitizada libre de tokens
router.get('/', obtenerProductos);

// 🛡️ OWASP A01:2025 - Escritura restringida perimetralmente con verificación de firmas JWT
router.post('/', verificarToken, upload.single('imagen'), crearProducto);
router.put('/:id', verificarToken, upload.single('imagen'), actualizarProducto);
router.delete('/:id', verificarToken, eliminarProducto);

module.exports = router;