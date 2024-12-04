const express = require('express');
const router = express.Router();

const controller = require('../controllers/controller');
const authController = require('../controllers/authController');

/* GET home page. */
router.get('/', controller.index_get);
router.post('/login', authController.login);
router.post('/signup', controller.user_create_post);

module.exports = router;
