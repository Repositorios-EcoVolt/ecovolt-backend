const express = require('express');
const router = express.Router();

const controller = require('../controllers/controller');
const middleware = require('../controllers/middleware');
const authController = require('../controllers/authController');

const usersRouter = require('./users');

/* GET home page. */
router.get('/', middleware.allowAny, controller.health_check);
router.post('/login', authController.login);
router.get('/logout', authController.logout);
router.get('/users', usersRouter);

module.exports = router;
