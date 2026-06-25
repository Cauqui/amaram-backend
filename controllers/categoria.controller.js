// controllers/categoria.controller.js
const pool = require('../config/db');

// 🛡️ OWASP A09:2025 - Importamos el registrador centralizado de logs de auditoría
const { registrarAccionAuditoria } = require('../utils/logger');

/**
 * 1. OBTENER CATEGORÍAS (Lectura del catálogo perimetral seguro)
 * Nota: Al ser una consulta pasiva (Lectura), no genera fila en la bitácora para optimizar rendimiento.
 */
const obtenerCategorias = async (req, res) => {
  try {
    // 🛡️ OWASP A05:2025 - Consulta estructurada parametrizada nativa
    const result = await pool.query('SELECT id, nombre, descripcion FROM Categorias ORDER BY id ASC');
    return res.json(result.rows);
  } catch (error) {
    console.error(`🚨 [CATEGORY EXCEPTION] [${new Date().toISOString()}] - Fallo al listar categorías:`, error.message);
    return res.status(500).json({ 
      status: "error", 
      mensaje: 'Ocurrió un error interno al recuperar el listado de categorías.' 
    });
  }
};

/**
 * 💡 FUNCIÓN PROYECTADA/OPCIONAL: CREAR CATEGORÍA
 * Inyéctala si vas a dar de alta categorías desde tu Panel de Administración
 */
const crearCategoria = async (req, res) => {
  const { rol } = req.usuario || {};
  if (rol !== 'ADMINISTRADOR') {
    return res.status(403).json({ status: "error", mensaje: 'Acceso denegado: Privilegios insuficientes.' });
  }

  const { nombre, descripcion } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO Categorias (nombre, descripcion) VALUES ($1, $2) RETURNING *',
      [nombre, descripcion]
    );
    const nuevaCategoria = result.rows[0];

    // 🛡️ OWASP A09:2025 - Registro automático en el catálogo de auditoría
    await registrarAccionAuditoria(
      req,
      'CREAR_PRODUCTO', // Agrupado en el módulo de catálogo para el filtro de React
      `Se creó una nueva categoría en el sistema: "${nuevaCategoria.nombre}" - Descripción: ${nuevaCategoria.descripcion || 'Ninguna'}.`,
      'BAJA'
    );

    return res.status(201).json({ status: "success", categoria: nuevaCategoria });
  } catch (error) {
    console.error(`🚨 [CATEGORY EXCEPTION] - Fallo al crear categoría:`, error.message);
    return res.status(500).json({ status: "error", mensaje: 'Error interno al procesar el registro.' });
  }
};

module.exports = { 
  obtenerCategorias,
  crearCategoria // Dejado listo por arquitectura escalable
};