// routes/clientes.routes.js
const express = require('express');
const router = express.Router(); 
const clienteController = require('../controllers/cliente.controller');

// Importación del middleware criptográfico de sesión
const { verificarToken } = require('../middleware');

// ============================================================================
// DEFINICIÓN DE RUTAS PERIMETRALES DE CLIENTES (Prefijo base: /api/clientes)
// ============================================================================

// 🛒 Flujo Público: Alta segura de cuentas de compradores externos
router.post('/registro', clienteController.registrarCliente);

// 🛡️ OWASP A01:2025 - Gestión de Cuentas Privada (Restringido mediante firmas JWT)
router.get('/', verificarToken, clienteController.listarClientes);
router.put('/:uuid', verificarToken, clienteController.actualizarCliente);
router.delete('/:uuid', verificarToken, clienteController.eliminarCliente);

module.exports = router;