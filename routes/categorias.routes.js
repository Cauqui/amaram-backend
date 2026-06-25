// routes/categorias.routes.js
const express = require('express');
const router = express.Router();
const categoriaController = require('../controllers/categoria.controller');

// ============================================================================
// DEFINICIÓN DE RUTAS PÚBLICAS DE CATEGORÍAS (Prefijo base: /api/categorias)
// ============================================================================

// 🛒 Catálogo de Categorías: Acceso perimetral seguro de lectura pública
router.get('/', categoriaController.obtenerCategorias);

module.exports = router;