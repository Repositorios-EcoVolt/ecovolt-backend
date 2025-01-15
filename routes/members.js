var express = require('express');
var router = express.Router();

const memberController = require('../controllers/memberController');
const middleware = require('../controllers/middleware');

/* Show all members */
router.get('/', middleware.allowAny, memberController.get_members);

/* Show an specific member */
router.get('/:id', middleware.allowAny, memberController.get_member);

/* Add new member */
router.post('/add', middleware.allowAdminOrModerator, memberController.add_member);

/* Update an specific member */
router.put('/update/:id', middleware.allowAdminOrModerator, memberController.update_member);

/* Delete member */
router.delete('/delete/:id', middleware.allowAdminOrModerator, memberController.delete_member);

module.exports = router;
