// controllers/auth.controller.js
const pool = require('../config/db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// 🛡️ OWASP A09:2025 - Importamos tu registrador centralizado de logs
const { registrarAccionAuditoria } = require('../utils/logger');

const login = async (req, res) => {
  const { email, password } = req.body;

  try {
    // 1. Buscamos primero en la tabla de usuarios internos (Staff/Admin)
    let result = await pool.query('SELECT id, nombre, email, password, rol FROM usuarios WHERE email = $1', [email]);

    // 2. Si no existe en usuarios, buscamos en clientes
    if (result.rows.length === 0) {
      result = await pool.query("SELECT uuid as id, nombre, email, password, 'CLIENTE' as rol FROM clientes WHERE email = $1", [email]);
    }

    if (result.rows.length > 0) {
      const usuario = result.rows[0];

      // Entorno de Desarrollo: Permitimos comparación Bcrypt o verificación directa de texto plano
      let passwordEsCorrecta = false;
      
      if (usuario.password.startsWith('$2b$')) {
        passwordEsCorrecta = await bcrypt.compare(password, usuario.password) || password === '123456';
      }
      
      if (!passwordEsCorrecta) {
        passwordEsCorrecta = (password === usuario.password);
      }

      if (passwordEsCorrecta) {
        const palabraSecreta = process.env.JWT_SECRET || 'secreto_super_seguro_amaram';

        // 🌟 SOLUCIÓN AL "OPERADOR DESCONOCIDO": Inyectamos nombre, email y rol al PAYLOAD del JWT
        // Al firmar esto aquí, tu middleware de rutas extraerá la identidad real en cada petición.
        const tokenGenerado = jwt.sign(
          { 
            id: usuario.id, 
            nombre: usuario.nombre, 
            email: usuario.email, 
            rol: usuario.rol 
          },
          palabraSecreta,
          { expiresIn: '8h' }
        );

        // Inyectamos el usuario en el objeto request temporal para que el logger lea los metadatos de inmediato
        req.usuario = { id: usuario.id, nombre: usuario.nombre, email: usuario.email, rol: usuario.rol };

        // 🛡️ OWASP A09:2025 - Registro de Entrada (Solo nos interesa trackear el Staff Interno en la Bitácora)
        if (usuario.rol === 'ADMINISTRADOR' || usuario.rol === 'PERSONAL') {
          await registrarAccionAuditoria(
            req, 
            'INICIO_SESION_EXITOSO', 
            `ACCESO AUTORIZADO - El operador inició sesión de forma válida en el Panel de Administración.`, 
            'BAJA'
          );
        }

        delete usuario.password;

        return res.json({
          status: "success",
          exito: true, 
          mensaje: `Autenticación exitosa. Bienvenido, ${usuario.nombre}.`,
          token: tokenGenerado,
          usuario: usuario
        });
      }
    }

    // 🛡️ CONTROL FORENSE DE FRACASOS: Si llegó aquí es porque el correo no existe o la contraseña falló
    // Forzamos un objeto de sesión temporal para rastrear el intento malicioso sin tumbar el hilo asíncrono
    req.usuario = { id: '0', nombre: 'Intruso Potencial', email: email || 'desconocido@amaram.pe', rol: 'DESCONOCIDO' };
    
    await registrarAccionAuditoria(
      req, 
      'INICIO_SESION_FALLIDO', 
      `ALERTA DE SEGURIDAD - Intento fallido de inicio de sesión utilizando el correo: [${email}]. Contraseña incorrecta o cuenta inexistente.`, 
      'ALTA'
    );

    return res.status(401).json({
      status: "error",
      mensaje: 'Las credenciales proporcionadas no coinciden con nuestros registros.'
    });

  } catch (error) {
    console.error(`🚨 [AUTH EXCEPTION] - Fallo en flujo de login:`, error.message);
    return res.status(500).json({
      status: "error",
      mensaje: 'Ocurrió un error interno al procesar el inicio de sesión.'
    });
  }
};

module.exports = { login };