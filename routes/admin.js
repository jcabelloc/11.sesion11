const express = require('express');

const adminController = require('../controllers/admin')
const isAuth = require('../middleware/is-auth');
;

const router = express.Router();


// /admin/crear-producto
router.get('/crear-producto', isAuth, adminController.getCrearProducto);

// /admin/productos
router.post('/crear-producto', isAuth, adminController.postCrearProducto);

router.get('/editar-producto/:idProducto', isAuth, adminController.getEditarProducto);

router.post('/editar-producto', isAuth, adminController.postEditarProducto);

router.post('/eliminar-producto', isAuth, adminController.postEliminarProducto);

router.get('/productos', isAuth, adminController.getProductos);

module.exports = router;
