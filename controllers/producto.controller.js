// controllers/producto.controller.js
const pool = require('../config/db');

// 🛡️ OWASP A09:2025 - Importamos el registrador centralizado de logs
const { registrarAccionAuditoria } = require('../utils/logger');

/**
 * 1. OBTENER PRODUCTOS (Catálogo Público Sanitizado)
 */
const obtenerProductos = async (req, res) => {
    try {
        const query = `
            SELECT p.id, p.sku, p.nombre, p.descripcion, p.precio_unitario, 
                   p.stock_disponible, p.imagen_url, p.categoria_id, p.status,
                   c.nombre AS categoria_nombre 
            FROM Productos p 
            LEFT JOIN Categorias c ON p.categoria_id = c.id
            WHERE p.soft_delete_at IS NULL 
            ORDER BY p.id ASC
        `;
        const result = await pool.query(query);
        return res.json(result.rows);
    } catch (error) {
        console.error(`🚨 [INVENTORY EXCEPTION] [${new Date().toISOString()}] - Fallo al listar catálogo:`, error.message);
        return res.status(500).json({ status: "error", mensaje: 'Error al procesar la solicitud del catálogo de productos.' });
    }
};

/**
 * 2. CREAR PRODUCTO (Control de Escritura Blindado)
 */
const crearProducto = async (req, res) => {
    const { rol } = req.usuario || {};
    if (rol !== 'ADMINISTRADOR') {
        return res.status(403).json({ status: "error", mensaje: 'Acceso denegado: Privilegios insuficientes para crear inventario.' });
    }

    try {
        const { nombre, descripcion, precio_unitario, stock_disponible, categoria_id } = req.body;
        const sku = `PROD-${Math.floor(100000 + Math.random() * 900000)}`;
        const imagen_url = req.file ? req.file.path : 'https://res.cloudinary.com/dtjoo7oge/image/upload/v1782105021/default.png';

        const query = `
            INSERT INTO Productos (sku, nombre, descripcion, precio_unitario, stock_disponible, imagen_url, categoria_id, status)
            VALUES ($1, $2, $3, $4, $5, $6, $7, 'Publicado')
            RETURNING *
        `;
        
        const result = await pool.query(query, [sku, nombre, descripcion, precio_unitario, stock_disponible, imagen_url, categoria_id]);
        const nuevoProducto = result.rows[0];

        // 🛡️ OWASP A09:2025 - Registro de Auditoría: Creación de Producto (Módulo de Catálogo)
        await registrarAccionAuditoria(
            req,
            'CREAR_PRODUCTO',
            `Se ingresó un nuevo producto al inventario comercial: "${nuevoProducto.nombre}" (SKU: ${nuevoProducto.sku}) con stock inicial de [${nuevoProducto.stock_disponible}] unidades.`,
            'BAJA'
        );
        
        return res.status(201).json({ status: "success", producto: nuevoProducto });
    } catch (error) {
        console.error(`🚨 [INVENTORY EXCEPTION] [${new Date().toISOString()}] - Fallo en inserción de producto:`, error.message);
        return res.status(500).json({ status: "error", mensaje: 'Error interno en el servidor al registrar el nuevo producto.' });
    }
};

/**
 * 3. ACTUALIZAR PRODUCTO (Control Mutacional Blindado)
 */
const actualizarProducto = async (req, res) => {
    const { rol } = req.usuario || {};
    if (rol !== 'ADMINISTRADOR') {
        return res.status(403).json({ status: "error", mensaje: 'Acceso denegado: Privilegios insuficientes para modificar el inventario.' });
    }

    try {
        const { id } = req.params;
        const { nombre, descripcion, precio_unitario, stock_disponible, categoria_id, status } = req.body;
        
        let result;

        if (req.file) {
            const imagen_url = req.file.path;
            const query = `
                UPDATE Productos 
                SET nombre=$1, descripcion=$2, precio_unitario=$3, stock_disponible=$4, imagen_url=$5, categoria_id=$6, status=$7
                WHERE id=$8 AND soft_delete_at IS NULL
                RETURNING *
            `;
            result = await pool.query(query, [nombre, descripcion, precio_unitario, stock_disponible, imagen_url, categoria_id, status, id]);
        } else {
            const query = `
                UPDATE Productos 
                SET nombre=$1, descripcion=$2, precio_unitario=$3, stock_disponible=$4, categoria_id=$5, status=$6
                WHERE id=$7 AND soft_delete_at IS NULL
                RETURNING *
            `;
            result = await pool.query(query, [nombre, descripcion, precio_unitario, stock_disponible, categoria_id, status, id]);
        }

        if (result.rowCount === 0) {
            return res.status(404).json({ status: "error", mensaje: 'El producto solicitado no existe o ha sido removido del sistema.' });
        }
        
        const productoEditado = result.rows[0];

        // 🛡️ OWASP A09:2025 - Registro de Auditoría: Modificación del Catálogo (Severidad Media)
        await registrarAccionAuditoria(
            req,
            'MODIFICAR_PRODUCTO',
            `Se modificaron las propiedades o existencias del producto ID #${id} (${productoEditado.nombre}). Parámetros fijados -> Stock: [${productoEditado.stock_disponible}], Precio: S/ ${productoEditado.precio_unitario}, Estado: [${productoEditado.status}].`,
            'MEDIA'
        );
        
        return res.json({ status: "success", producto: productoEditado });
    } catch (error) {
        console.error(`🚨 [INVENTORY EXCEPTION] [${new Date().toISOString()}] - Fallo en actualización:`, error.message);
        return res.status(500).json({ status: "error", mensaje: 'Ocurrió un error interno al intentar actualizar el registro.' });
    }
};

/**
 * 4. ELIMINAR PRODUCTO (Soft Delete Controlado)
 */
const eliminarProducto = async (req, res) => {
    const { rol } = req.usuario || {};
    if (rol !== 'ADMINISTRADOR') {
        return res.status(403).json({ status: "error", mensaje: 'Acceso denegado: Privilegios insuficientes para eliminar registros.' });
    }

    try {
        const { id } = req.params;
        const query = `
            UPDATE Productos 
            SET soft_delete_at = NOW() 
            WHERE id = $1 AND soft_delete_at IS NULL
            RETURNING *
        `;
        const result = await pool.query(query, [id]);
        
        if (result.rowCount === 0) {
            return res.status(404).json({ status: "error", mensaje: 'El producto no fue encontrado o ya ha sido procesado previamente.' });
        }
        
        const productoEliminado = result.rows[0];

        // 🛡️ OWASP A09:2025 - Registro de Auditoría: Destrucción o Baja de Inventario (Severidad Alta)
        await registrarAccionAuditoria(
            req,
            'ELIMINAR_PRODUCTO',
            `BAJA DE INVENTARIO - Remoción lógica ejecutada sobre el artículo ID #${id}: "${productoEliminado.nombre}" (SKU: ${productoEliminado.sku}).`,
            'ALTA'
        );
        
        return res.json({ status: "success", mensaje: 'Producto eliminado correctamente (Soft Delete)', producto: productoEliminado });
    } catch (error) {
        console.error(`🚨 [INVENTORY EXCEPTION] [${new Date().toISOString()}] - Fallo en borrado lógico:`, error.message);
        return res.status(500).json({ status: "error", mensaje: 'Error interno en el servidor al ejecutar el borrado seguro.' });
    }
};

module.exports = { 
    obtenerProductos, 
    crearProducto, 
    actualizarProducto, 
    eliminarProducto 
};