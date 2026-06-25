// controllers/usuario.controller.js
const pool = require('../config/db');
const bcrypt = require('bcrypt');

// 🛡️ Importamos el registrador centralizado que creaste en utils/logger.js
const { registrarAccionAuditoria } = require('../utils/logger');

/**
 * 1. OBTENER USUARIOS DE STAFF (Segregado y Seguro)
 */
const obtenerUsuarios = async (req, res) => {
  // 🛡️ OWASP A01:2025 - Restricción estricta de auditoría de cuentas a Administradores
  const { rol } = req.usuario || {};
  if (rol !== 'ADMINISTRADOR') {
    return res.status(403).json({ status: "error", mensaje: "Acceso denegado: Privilegios insuficientes para listar usuarios." });
  }

  try {
    const result = await pool.query(
      "SELECT id, nombre, email, direccion, rol, celular, activo FROM usuarios WHERE rol != 'CLIENTE' ORDER BY id ASC"
    );
    return res.json(result.rows);
  } catch (error) {
    console.error(`🚨 [STAFF EXCEPTION] [${new Date().toISOString()}] - Fallo al listar personal:`, error.message);
    return res.status(500).json({ status: "error", mensaje: "Error interno al recuperar los registros del personal." });
  }
};

/**
 * 2. CREAR NUEVO USUARIO DE STAFF (Enmascaramiento e Integridad)
 */
const crearUsuario = async (req, res) => {
  // 🛡️ OWASP A01:2025 - Solo un Administrador puede dar de alta cuentas internas del negocio
  const { rol: rolGestor } = req.usuario || {};
  if (rolGestor !== 'ADMINISTRADOR') {
    return res.status(403).json({ status: "error", mensaje: "Acceso denegado: Operación restringida solo a cuentas administrativas." });
  }

  const { nombre, email, password, direccion, rol, celular } = req.body;
  
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const result = await pool.query(
      'INSERT INTO usuarios (nombre, email, password, direccion, rol, celular, activo) VALUES ($1, $2, $3, $4, $5, $6, true) RETURNING id, nombre, email, direccion, rol, celular, activo',
      [nombre, email, hashedPassword, direccion, rol, celular]
    );

    const nuevoUsuario = result.rows[0];

    // 🛡️ OWASP A09:2025 - Inyección de Rastro de Auditoría (Severidad Baja)
    await registrarAccionAuditoria(
      req, 
      'CREAR_PERSONAL', 
      `Se dio de alta un nuevo miembro de staff: ${nuevoUsuario.nombre} con el rol operativo [${nuevoUsuario.rol}] e email: ${nuevoUsuario.email}.`, 
      'BAJA'
    );
    
    return res.status(201).json({ status: "success", usuario: nuevoUsuario });
  } catch (error) {
    console.error(`🚨 [STAFF EXCEPTION] [${new Date().toISOString()}] - Fallo al crear usuario:`, error.message);
    return res.status(500).json({ status: "error", mensaje: "Error interno en el servidor al procesar el registro del usuario." });
  }
};

/**
 * 3. EDITAR USUARIO DE STAFF (Protección de Mutación)
 */
const actualizarUsuario = async (req, res) => {
  // 🛡️ OWASP A01:2025 - Validación perimetral de roles
  const { rol: rolGestor } = req.usuario || {};
  if (rolGestor !== 'ADMINISTRADOR') {
    return res.status(403).json({ status: "error", mensaje: "Acceso denegado: Privilegios insuficientes para modificar cuentas." });
  }

  const { id } = req.params;
  const { nombre, email, password, direccion, rol, celular, activo } = req.body;
  
  try {
    let result;
    
    if (password && password.trim() !== "") {
      const hashedPassword = await bcrypt.hash(password, 10);
      result = await pool.query(
        'UPDATE usuarios SET nombre=$1, email=$2, password=$3, direccion=$4, rol=$5, celular=$6, activo=$7 WHERE id=$8 RETURNING id, nombre, email, rol', 
        [nombre, email, hashedPassword, direccion, rol, celular, activo, id]
      );
    } else {
      result = await pool.query(
        'UPDATE usuarios SET nombre=$1, email=$2, direccion=$3, rol=$4, celular=$5, activo=$6 WHERE id=$7 RETURNING id, nombre, email, rol',
        [nombre, email, direccion, rol, celular, activo, id]
      );
    }

    if (result.rowCount === 0) {
      return res.status(404).json({ status: "error", mensaje: "El usuario interno solicitado no existe." });
    }

    const usuarioModificado = result.rows[0];

    // 🛡️ OWASP A09:2025 - Inyección de Rastro de Auditoría (Severidad Media)
    await registrarAccionAuditoria(
      req, 
      'MODIFICAR_ROL', 
      `Se actualizaron los privilegios o datos del personal ID #${usuarioModificado.id}: ${usuarioModificado.nombre} (${usuarioModificado.email}). Rol asignado: [${usuarioModificado.rol}].`, 
      'MEDIA'
    );

    return res.json({ status: "success", mensaje: 'Usuario del personal actualizado de manera segura.' });
  } catch (error) {
    console.error(`🚨 [STAFF EXCEPTION] [${new Date().toISOString()}] - Fallo al actualizar usuario:`, error.message);
    return res.status(500).json({ status: "error", mensaje: "Ocurrió un error interno al actualizar el perfil del usuario." });
  }
};

/**
 * 4. ELIMINAR USUARIO DE STAFF (Remoción Segura)
 */
const eliminarUsuario = async (req, res) => {
  // 🛡️ OWASP A01:2025 - Mitigación del peligro de destrucción de registros
  const { rol: rolGestor } = req.usuario || {};
  if (rolGestor !== 'ADMINISTRADOR') {
    return res.status(403).json({ status: "error", mensaje: "Acceso denegado: Privilegios insuficientes para eliminar personal de la base de datos." });
  }

  const { id } = req.params;

  try {
    // 🛡️ ANTES DE BORRAR: Consultamos los datos informativos del usuario para no perder el rastro de su correo
    const usuarioPreBorrado = await pool.query('SELECT nombre, email, rol FROM usuarios WHERE id = $1', [id]);
    
    if (usuarioPreBorrado.rowCount === 0) {
      return res.status(404).json({ status: "error", mensaje: "El usuario no existe o ya ha sido removido previamente." });
    }

    const { nombre, email, rol } = usuarioPreBorrado.rows[0];

    // Ejecutamos la remoción destructiva real
    await pool.query('DELETE FROM usuarios WHERE id = $1', [id]);
    
    // 🛡️ OWASP A09:2025 - Inyección Forense en logs_auditoria con Severidad ALTA (Alerta Roja)
    await registrarAccionAuditoria(
      req, 
      'ELIMINAR_USUARIO', 
      `ELIMINACIÓN PERMANENTE - Se purgó del sistema la cuenta ID #${id} perteneciente a: ${nombre} (${email}) con el rol operativo [${rol}].`, 
      'ALTA'
    );

    return res.json({ status: "success", mensaje: 'Registro de usuario eliminado permanentemente del sistema.' });
  } catch (error) {
    console.error(`🚨 [STAFF EXCEPTION] [${new Date().toISOString()}] - Fallo al eliminar usuario:`, error.message);
    return res.status(500).json({ status: "error", mensaje: "Error interno al ejecutar el borrado del registro." });
  }
};

module.exports = { obtenerUsuarios, crearUsuario, actualizarUsuario, eliminarUsuario };