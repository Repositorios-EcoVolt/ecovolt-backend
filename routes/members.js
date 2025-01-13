var express = require('express');
var router = express.Router();

const memberController = require('../controllers/memberController');
const middleware = require('../controllers/middleware');

/* Show all members */
router.get('/', middleware.allowAny, memberController.get_members);

/* Add new member */
router.post('/add', middleware.allowAdminOrModerator, memberController.add_member);

/* Delete member */
router.delete('/delete/:id', middleware.allowAdminOrModerator, memberController.delete_member);

module.exports = router;