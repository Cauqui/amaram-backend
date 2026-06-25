// routes/usuarios.routes.js
const express = require('express');
const router = express.Router();
const usuarioController = require('../controllers/usuario.controller');

// Importación del guardián perimetral criptográfico
const { verificarToken } = require('../middleware');

// ============================================================================
// DEFINICIÓN DE RUTAS PERIMETRALES DE STAFF (Prefijo base: /api/usuarios)
// ============================================================================

// 🛡️ OWASP A01:2025 - Gestión de personal protegida contra accesos no autorizados y Broken Access Control
router.get('/', verificarToken, usuarioController.obtenerUsuarios);
router.post('/', verificarToken, usuarioController.crearUsuario);
router.put('/:id', verificarToken, usuarioController.actualizarUsuario);
router.delete('/:id', verificarToken, usuarioController.eliminarUsuario);

module.exports = router;