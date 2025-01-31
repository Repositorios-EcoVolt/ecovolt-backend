const express = require('express');
const router = express.Router();

const userController = require('../controllers/userController');
const middleware = require('../controllers/middleware');

/* Show all users */
router.get('/', middleware.allowAdmin, userController.get_users);

/* Show current user */
router.get('/me', userController.get_user);

/* Show an specific user */
router.get('/:id', userController.get_user_by_id);

/* Create new user */
router.post('/create', middleware.allowAdmin, userController.create_user);

/* Update user (for example suspend account) */
router.put('/update/:id', userController.update_user);

/* Update user password */
router.patch('/update-password/:id', userController.update_user_password);

/* Delete user */
router.delete('/delete/:username', middleware.allowAdmin, userController.delete_user);

module.exports = router;
