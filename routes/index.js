const express = require('express');
const router = express.Router();

const controller = require('../controller');

/* GET home page. */
router.get('/', controller.index_get);
router.get('/signup', controller.user_create_get);

module.exports = router;
