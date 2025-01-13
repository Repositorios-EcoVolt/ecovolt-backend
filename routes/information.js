var express = require('express');
var router = express.Router();

const informationController = require('../controllers/informationSectionController');
const middleware = require('../controllers/middleware');
const upload = require('../storageEngine');


/* Show all information sections */
router.get('/', middleware.allowAny, informationController.get_information_sections);

/* Add new information section */
router.post('/add', middleware.allowAdminOrModerator, informationController.add_information_section);

/* Add picture for an information section */
router.post('/add-picture/:id', middleware.allowAdminOrModerator, upload.single('file'), informationController.add_information_section_picture);

/* Publish information section */
router.patch('/publish/:id', middleware.allowAdminOrModerator, informationController.publish_information_section);

/* Unpublish information section */
router.patch('/unpublish/:id', middleware.allowAdminOrModerator, informationController.hide_information_section);

/* Update information section */
router.put('update/:id', middleware.allowAdminOrModerator, informationController.update_information_section);

/* Delete information section */
router.delete('delete/:id', middleware.allowAdminOrModerator, informationController.delete_information_section);

module.exports = router;
