// routes/auditoria.routes.js
const express = require('express');
const router = express.Router();
const auditoriaController = require('../controllers/auditoria.controller');

// Importamos tus middlewares de control de acceso
const { verificarToken, permitirRoles } = require('../middleware');

// 🛡️ OWASP A01:2025 - Ruta perimetral restringida exclusivamente al perfil ADMINISTRADOR
router.get('/', verificarToken, permitirRoles('ADMINISTRADOR'), auditoriaController.obtenerLogsAuditoria);

module.exports = router;