const express = require('express');

const authController = require('../controllers/auth');

const router = express.Router();

router.get('/ingresar', authController.getIngresar);

router.post('/ingresar', authController.postIngresar);

router.get('/registrarse', authController.getRegistrarse);

router.post('/registrarse', authController.postRegistrarse);

router.post('/salir', authController.postSalir);

router.get('/reinicio', authController.getReinicio);



module.exports = router;