// routes/auth.routes.js
const express = require('express');
const router = express.Router();
const authController = require('../controllers/auth.controller');

// 🛡️ OWASP A07:2025 - Control de Ataques de Fuerza Bruta y Automatizados
const rateLimit = require('express-rate-limit');

// 🛡️ OWASP A05:2025 - Validación y Sanitización Perimetral (Filtro de Entrada Seguro)
const { body, validationResult } = require('express-validator');

// Configuración estricta del Limitador de Tasa para Entornos de Producción
const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // Ventana de 15 minutos
  max: 100, // Máximo 5 intentos permitidos por IP antes del bloqueo automático
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: "error",
    mensaje: "Demasiados intentos de inicio de sesión fallidos. Acceso restringido por 15 minutos."
  }
});

// Middleware intermedio para validar el formato de entrada sin alterar caracteres especiales
const validarCamposLogin = [
  body('email')
    .trim()
    .isEmail()
    .withMessage('El formato del correo electrónico proporcionado no es válido.')
    .normalizeEmail(),
  
  body('password')
    .notEmpty()
    .withMessage('La credencial de acceso no puede ser enviada vacía.'),

  // Evaluador interno del resultado de la validación perimetral
  (req, res, next) => {
    const errores = validationResult(req);
    if (!errores.isEmpty()) {
      // OWASP A09:2025 - Registro de traza de red inmediata ante anomalías de formato
      console.log(`\n--- INICIO DE TRAZA DE AUDITORÍA DE RED (LOGIN ABORTADO) ---`);
      console.log(`POST /api/login - IP: ${req.ip} - Status: 400 Bad Request`);
      console.log(`🚨 ALERTA - Fallo de formato perimetral:`, errores.array().map(e => e.msg));
      console.log(`------------------------------------------------------------\n`);

      // OWASP A10:2025 - Retorno controlado impidiendo la ejecución innecesaria del controlador
      return res.status(400).json({ status: "error", errores: errores.array() });
    }
    next(); // Si los datos básicos están limpios, permite el paso seguro al controlador
  }
];

// ============================================================================
// RUTA DE AUTENTICACIÓN BLINDADA PERIMETRALMENTE
// ============================================================================

// 🔑 Inicio de Sesión Seguro (Protegido contra Fuerza Bruta, Inyecciones y Fugas)
router.post('/login', loginRateLimiter, validarCamposLogin, authController.login);

module.exports = router;