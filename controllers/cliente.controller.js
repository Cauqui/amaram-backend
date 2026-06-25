// controllers/cliente.controller.js
const pool = require('../config/db'); 
const bcrypt = require('bcrypt');

// 🛡️ OWASP A09:2025 - Importación del registrador centralizado de utilidades
const { registrarAccionAuditoria } = require('../utils/logger');

/**
 * 1. Registro de Cliente (Público, para la tienda virtual)
 * 🛡️ Blindado contra inyecciones SQL y almacenamiento inseguro de contraseñas
 */
const registrarCliente = async (req, res) => {
  const { nombre, apellido, email, password, direccion, celular } = req.body;
  try {
    const existe = await pool.query('SELECT uuid FROM clientes WHERE email = $1', [email]);
    if (existe.rows.length > 0) {
      return res.status(400).json({ status: "error", error: 'Este correo ya está registrado.' });
    }
    
    // 🛡️ OWASP A02:2025 - Criptografía robusta y hash asíncronos para contraseñas
    const passwordHash = await bcrypt.hash(password, 10);
    const nuevoCliente = await pool.query(
      'INSERT INTO clientes (nombre, apellido, email, password, direccion, celular) VALUES ($1, $2, $3, $4, $5, $6) RETURNING uuid',
      [nombre, apellido, email, passwordHash, direccion, celular]
    );

    const clienteUuid = nuevoCliente.rows[0].uuid;

    // 🛡️ OWASP A09:2025 - Registro Automático de nuevo usuario externo (Severidad Baja)
    // Forzamos un mock temporal del req.usuario si la cuenta se crea de forma pública en el checkout
    const reqAuditoria = req.usuario ? req : { ...req, usuario: { id: clienteUuid, nombre: `${nombre} ${apellido}`, email, rol: 'CLIENTE' } };
    await registrarAccionAuditoria(
      reqAuditoria,
      'REGISTRO_CLIENTE',
      `AUTOREGISTRO - Un nuevo cliente externo se ha dado de alta: ${nombre} ${apellido} (${email}).`,
      'BAJA'
    );

    return res.status(201).json({ status: "success", uuid: clienteUuid, mensaje: 'Cliente registrado con éxito' });
  } catch (err) {
    console.error(`🚨 [CLIENTS EXCEPTION] [${new Date().toISOString()}] - Error en registro:`, err.message);
    return res.status(500).json({ status: "error", error: 'Error interno al registrar cliente' });
  }
};

/**
 * 2. Listar clientes (Privado, para el Panel Admin)
 * 🛡️ OWASP A01:2025 - Control de Acceso Basado en Roles (RBAC) Obligatorio
 */
const listarClientes = async (req, res) => {
  const { rol } = req.usuario || {};
  if (rol !== 'ADMINISTRADOR') {
    return res.status(403).json({ status: "error", mensaje: 'Acceso denegado: Privilegios insuficientes para auditar cuentas.' });
  }

  try {
    const result = await pool.query(
      'SELECT uuid, nombre, apellido, email, direccion, celular, activo, creado_en FROM clientes ORDER BY creado_en ASC'
    );
    return res.json(result.rows);
  } catch (err) {
    console.error(`🚨 [CLIENTS EXCEPTION] [${new Date().toISOString()}] - Error en listar:`, err.message);
    return res.status(500).json({ status: "error", error: 'Error interno al obtener el listado de clientes' });
  }
};

/**
 * 3. Actualizar cliente (Privado/Protegido para Administración)
 * 🛡️ OWASP A01:2025 - Validación perimetral mutacional de roles
 */
const actualizarCliente = async (req, res) => {
  const { rol } = req.usuario || {};
  if (rol !== 'ADMINISTRADOR') {
    return res.status(403).json({ status: "error", mensaje: 'Acceso denegado: Privilegios insuficientes para modificar cuentas.' });
  }

  const { uuid } = req.params;
  const { nombre, apellido, email, celular, direccion, password } = req.body;
  try {
    let result;
    if (password && password.trim() !== "") {
      const passwordHash = await bcrypt.hash(password, 10);
      result = await pool.query(
        'UPDATE clientes SET nombre=$1, apellido=$2, email=$3, celular=$4, direccion=$5, password=$6 WHERE uuid=$7 RETURNING uuid', 
        [nombre, apellido, email, celular, direccion, passwordHash, uuid]
      );
    } else {
      result = await pool.query(
        'UPDATE clientes SET nombre=$1, apellido=$2, email=$3, celular=$4, direccion=$5 WHERE uuid=$6 RETURNING uuid', 
        [nombre, apellido, email, celular, direccion, uuid]
      );
    }

    if (result.rowCount === 0) {
      return res.status(404).json({ status: "error", mensaje: 'El cliente solicitado no existe en la base de datos.' });
    }

    // 🛡️ OWASP A09:2025 - Registro de Modificación de Datos del Cliente (Severidad Media)
    await registrarAccionAuditoria(
      req,
      'MODIFICAR_ROL', // Mapeado al módulo de usuarios de la bitácora
      `Se actualizaron los datos maestros del cliente externo UUID [${uuid}]: ${nombre} ${apellido} (${email}).`,
      'MEDIA'
    );

    return res.json({ status: "success", mensaje: 'Registro de cliente actualizado correctamente.' });
  } catch (error) {
    console.error(`🚨 [CLIENTS EXCEPTION] [${new Date().toISOString()}] - Error en actualizar:`, error.message);
    return res.status(500).json({ status: "error", error: 'Error interno en el servidor al actualizar la información.' });
  }
};

/**
 * 4. Eliminar cliente (Privado/Protegido)
 * 🛡️ OWASP A01:2025 - Mitigación del peligro de destrucción no autorizada de registros
 */
const eliminarCliente = async (req, res) => {
  const { rol } = req.usuario || {};
  if (rol !== 'ADMINISTRADOR') {
    return res.status(403).json({ status: "error", mensaje: 'Acceso denegado: Privilegios insuficientes para eliminar registros.' });
  }

  const { uuid } = req.params;

  try {
    // 🛡️ ANTES DE BORRAR: Extraemos la información informativa para que no quede huérfana en los logs
    const clientePreBorrado = await pool.query('SELECT nombre, apellido, email FROM clientes WHERE uuid = $1', [uuid]);
    
    if (clientePreBorrado.rowCount === 0) {
      return res.status(404).json({ status: "error", mensaje: 'El cliente solicitado no existe o ya ha sido removido.' });
    }

    const { nombre, apellido, email } = clientePreBorrado.rows[0];

    // Ejecutamos la remoción real en la tabla relacional
    await pool.query('DELETE FROM clientes WHERE uuid = $1', [uuid]);
    
    // 🛡️ OWASP A09:2025 - Inyección de log forense con severidad ALTA
    await registrarAccionAuditoria(
      req,
      'ELIMINAR_USUARIO',
      `ELIMINACIÓN PERMANENTE - Se purgó del sistema la cuenta del cliente externo: ${nombre} ${apellido} (${email}) con UUID: [${uuid}].`,
      'ALTA'
    );

    return res.json({ status: "success", mensaje: 'Registro de cliente eliminado permanentemente del sistema.' });
  } catch (error) {
    console.error(`🚨 [CLIENTS EXCEPTION] [${new Date().toISOString()}] - Error en eliminar:`, error.message);
    return res.status(500).json({ status: "error", error: 'Error interno al procesar la remoción de la cuenta.' });
  }
};

module.exports = { registrarCliente, listarClientes, actualizarCliente, eliminarCliente };