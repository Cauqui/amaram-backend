// routes/ventas.routes.js
const express = require('express');
const router = express.Router();
const ventaController = require('../controllers/venta.controller');

// 🛡️ Importación del control criptográfico de sesión
const { verificarToken } = require('../middleware'); 

// 🛡️ Importamos el validador perimetral (OWASP A05:2025)
const { body, validationResult } = require('express-validator');

// 🛡️ Middleware intermedio para interceptar, limpiar y evaluar los datos del checkout
const validarCheckoutInput = [
  body('metodo_pago')
    .trim()
    .isIn(['TARJETA', 'QR', 'YAPE']) 
    .withMessage('El método de pago proporcionado no es válido para el comercio.'),
  
  body('productos')
    .isArray({ min: 1 })
    .withMessage('Fallo de integridad: El carrito de compras debe contener al menos un producto.'),
    
  body('codigo_referencia')
    .trim()
    .optional({ nullable: true, checkFalsy: true }) 
    .custom((value) => {
      if (!value) return true; 
      return /^[a-zA-Z0-9_\-\s]{6,30}$/.test(value); 
    })
    .withMessage('La referencia de pago debe ser un valor alfanumérico válido.'),

  // Evalúa el resultado de la sanitización perimetral
  (req, res, next) => {
    const errores = validationResult(req);
    if (!errores.isEmpty()) {
      // OWASP A09:2025 - Log de red inmediato para auditoría forense local en tiempo real
      console.log(`\n--- INICIO DE TRAZA DE AUDITORÍA DE RED (LOGS EN TIEMPO REAL) ---`);
      console.log(`POST /api/ventas - IP: ${req.ip} - Status: 400 Bad Request`);
      console.log(`🚨 ALERTA - express-validator: Fallo de coincidencia en parámetros:`, errores.array().map(e => e.msg));
      console.log(`-------------------------------------------------------------------\n`);

      // OWASP A10:2025 - Retorna error controlado sin exponer trazas del sistema
      return res.status(400).json({ status: "error", errores: errores.array() });
    }
    next(); 
  }
];

// ============================================================================
// RUTAS DE VENTAS PROTEGIDAS DE FORMA PERIMETRAL Y CON CONTROL DE SESIÓN
// ============================================================================

// 🛒 Registrar una Venta (Cualquier usuario autenticado - Cliente o Admin - puede comprar)
router.post('/', verificarToken, validarCheckoutInput, ventaController.registrarVenta);

// 📋 Historial Adaptativo Seguro (OWASP A01:2025 - Control de Acceso Roto)
// 💡 SOLUCIÓN: Quitamos permitirRoles para que el controlador verifique el JWT y segregue los datos dinámicamente.
router.get('/historial', verificarToken, ventaController.obtenerHistorial);

module.exports = router;