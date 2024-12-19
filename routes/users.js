var express = require('express');
var router = express.Router();

const userController = require('../controllers/userController');
const middleware = require('../controllers/middleware');

/* Show all users */
router.get('/', middleware.checkToken, userController.get_users);

/* Show current user */
router.get('/me', userController.get_user);

/* Create new user */
router.post('/create', middleware.checkToken, userController.create_user);

/* Update user (for example change password or suspend account) */

/* Delete user */
router.delete('/delete/:username', middleware.checkToken, userController.delete_user);

module.exports = router;
