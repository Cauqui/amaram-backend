// utils/logger.js
const pool = require('../config/db');

/**
 * 🛡️ OWASP A09:2025 - Registrador Centralizado de Logs de Auditoría
 * Graba de forma persistente en PostgreSQL cualquier acción crítica o destructiva.
 */
const registrarAccionAuditoria = async (req, accion, detalles, severidad) => {
  try {
    // Extraemos la identidad del operador inyectada de forma criptográfica por el JWT o variantes
    const usuario_uuid = req.usuario?.id || req.usuario?.uuid || req.usuario?.usuario_id || '1';
    const usuario_nombre = req.usuario?.nombre || 'Operador Desconocido';
    const usuario_email = req.usuario?.email || 'sin-email@amaram.pe';
    const rol_operador = req.usuario?.rol || 'DESCONOCIDO';
    
    // 🌐 Capturamos la dirección IP cruda
    let rawIp = req.headers['x-forwarded-for'] || req.ip || req.socket.remoteAddress || '127.0.0.1';

    // 🛡️ LIMPIEZA FORENSE: Si la IP es la de bucle local IPv6 (::1 o ::ffff:127.0.0.1), la normalizamos a IPv4 limpio
    if (rawIp === '::1' || rawIp === '::ffff:127.0.0.1') {
      rawIp = '127.0.0.1';
    } else if (rawIp.startsWith('::ffff:')) {
      // Por si Express la empaqueta como subred IPv4 mapeada en IPv6
      rawIp = rawIp.replace('::ffff:', '');
    }

    const query = `
      INSERT INTO logs_auditoria 
      (usuario_uuid, usuario_nombre, usuario_email, rol_operador, accion, detalles, severidad, direccion_ip)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    `;

    await pool.query(query, [
      String(usuario_uuid), // Soportado de forma segura gracias a tu ALTER TABLE VARCHAR
      usuario_nombre,
      usuario_email,
      rol_operador,
      String(accion).toUpperCase(),
      detalles,
      String(severidad).toUpperCase(),
      rawIp // Guardará "127.0.0.1" de forma impecable en desarrollo local
    ]);

    console.log(`✅ [AUDIT SUCCESS] Evento [${accion}] registrado desde IP: ${rawIp}`);

  } catch (error) {
    // Evitamos interrumpir el flujo principal del e-commerce si falla el logger
    console.error(`🚨 [CRITICAL LOG EXCEPTION] [${new Date().toISOString()}] - Fallo en el Audit Trail:`, error.message);
  }
};

module.exports = { registrarAccionAuditoria };