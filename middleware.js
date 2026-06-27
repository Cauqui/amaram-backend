// middleware.js
const jwt = require('jsonwebtoken');
require('dotenv').config(); 

// 🛡️ OWASP A09:2025 - Importamos el registrador centralizado de auditoría
const { registrarAccionAuditoria } = require('./utils/logger');

// 🛡️ MIDDLEWARE 1: Verificación de Autenticación Básica (JWT)
const verificarToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];

  // A01:2025 - Corrección de Código de Estado: Cambiado 403 por 401 (No autenticado)
  if (!authHeader) {
    return res.status(401).json({ 
      status: "error", 
      mensaje: 'Acceso denegado. No se proporcionó un token de autenticación válido.' 
    });
  }

  const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : authHeader;

  if (!token) {
    return res.status(401).json({ 
      status: "error", 
      mensaje: 'Formato de credenciales de autenticación inválido.' 
    });
  }

  // 🌟 SOLUCIÓN: Leemos la variable en tiempo de ejecución directa del entorno de producción
  const secretKeyActiva = process.env.JWT_SECRET || 'secreto_super_seguro_amaram';

  jwt.verify(token, secretKeyActiva, (err, usuario) => {
    if (err) {
      // A09:2025 - Registro de log estructurado en consola
      console.log("\n================================================================================");
      console.log(`🚨 [ALERTA DE SEGURIDAD] ACCESO RECHAZADO - ${new Date().toISOString()}`);
      console.log(`[ENDPOINT]: ${req.method} ${req.originalUrl}`);
      console.log(`[CAUSA CRIPTOGRÁFICA]: ${err.message}`);
      console.log(`[TOKEN AFECTADO]: ${token.substring(0, 20)}... [SIGNATURE_INVALID]`);
      console.log("================================================================================\n");
      
      return res.status(401).json({ 
        status: "error",
        mensaje: 'Sesión inválida, alterada o expirada. Por favor, vuelva a iniciar sesión.'
      });
    }
    
    // Inyección segura del payload sanitizado del usuario en el objeto Request
    req.usuario = usuario;
    next();
  });
};

// 🛡️ MIDDLEWARE 2: Control de Acceso Basado en Roles (RBAC - OWASP A01:2025)
const permitirRoles = (...rolesPermitidos) => {
  return async (req, res, next) => { 
    if (!req.usuario || !req.usuario.rol) {
      return res.status(403).json({ 
        status: "error", 
        mensaje: 'Acceso denegado. No se pudieron verificar los privilegios de usuario.' 
      });
    }

    // Comprobamos si el rol inyectado en el JWT está autorizado para consumir la ruta
    if (!rolesPermitidos.includes(req.usuario.rol)) {
      
      // 🛡️ OWASP A09:2025 - Registro Forense Crítico de Intento de Escalación de Privilegios
      await registrarAccionAuditoria(
        req,
        'INTENTO_IDOR',
        `VIOLACIÓN DE POLÍTICAS - El usuario intentó forzar el acceso al recurso restringido: [${req.method} ${req.originalUrl}]. Operación bloqueada perimetralmente.`,
        'ALTA'
      );

      return res.status(403).json({ 
        status: "error", 
        mensaje: 'Acceso restringido. Su cuenta no posee privilegios para realizar esta acción.' 
      });
    }

    next(); 
  };
};

module.exports = { 
  verificarToken, 
  permitirRoles
};