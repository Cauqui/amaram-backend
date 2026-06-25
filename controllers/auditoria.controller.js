// controllers/auditoria.controller.js
const pool = require('../config/db');

/**
 * 🛡️ OWASP A01:2025 - Recupera la bitácora de logs con filtros adaptativos perimetrales
 */
const obtenerLogsAuditoria = async (req, res) => {
  // Doble verificación defensiva del rol operativo
  if (req.usuario?.rol !== 'ADMINISTRADOR') {
    return res.status(403).json({ status: "error", mensaje: "Acceso denegado: Privilegios de auditoría insuficientes." });
  }

  const { modulo } = req.query; // Recibe el criterio de filtrado desde React

  try {
    let query = 'SELECT id, usuario_nombre, usuario_email, rol_operador, accion, detalles, severidad, direccion_ip, fecha FROM logs_auditoria';
    let params = [];

    // 🛡️ Lógica de segmentación por módulos para el Administrador
    if (modulo === 'USUARIOS') {
      query += ` WHERE accion IN ('ELIMINAR_USUARIO', 'CREAR_PERSONAL', 'MODIFICAR_ROL', 'REGISTRO_CLIENTE')`;
    } else if (modulo === 'CATALOGO') {
      query += ` WHERE accion IN ('CREAR_PRODUCTO', 'MODIFICAR_PRODUCTO', 'ELIMINAR_PRODUCTO', 'ACTUALIZAR_STOCK')`;
    } else if (modulo === 'SEGURIDAD') {
      query += ` WHERE accion IN ('INICIO_SESION_FALLIDO', 'BLOQUEO_IP', 'INTENTO_IDOR')`;
    }

    query += ' ORDER BY fecha DESC LIMIT 200'; // Ponemos un tope preventivo de rendimiento

    const result = await pool.query(query, params);
    return res.json(result.rows);

  } catch (error) {
    console.error(`🚨 [AUDIT CONTROLLER ERROR] Fetch fallido:`, error.message);
    return res.status(500).json({ status: "error", mensaje: "Error interno al recuperar los registros analíticos." });
  }
};

module.exports = { obtenerLogsAuditoria };