const express = require('express');
const router = express.Router();

const controller = require('../controllers/controller');
const middleware = require('../controllers/middleware');
const authController = require('../controllers/authController');

/* GET home page. */
router.get('/', middleware.checkToken, controller.index_get);
router.post('/login', authController.login);
router.post('/signup', middleware.checkToken, controller.user_create_post);

module.exports = router;
