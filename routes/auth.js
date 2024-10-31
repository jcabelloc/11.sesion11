const express = require('express');

const authController = require('../controllers/auth');

const router = express.Router();

router.get('/ingresar', authController.getIngresar);

router.post('/ingresar', authController.postIngresar);

router.get('/registrarse', authController.getRegistrarse);

router.post('/registrarse', authController.postRegistrarse);

router.post('/salir', authController.postSalir);



module.exports = router;