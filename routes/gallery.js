var express = require('express');
var router = express.Router();

const galleryPhotoController = require('../controllers/galleryPhotoController');
const middleware = require('../controllers/middleware');

/* Show all gallery photos */
router.get('/', galleryPhotoController.get_gallery_photos);

/* Show an specific gallery photo */
router.get('/:id', galleryPhotoController.get_gallery_photo);

/* Add new gallery photo */
router.post('/add', middleware.allowAdminOrModerator, galleryPhotoController.add_gallery_photo);

/* Publish gallery photo */
router.patch('/publish/:id', middleware.allowAdminOrModerator, galleryPhotoController.publish_gallery_photo);

/* Unpublish gallery photo */
router.patch('/unpublish/:id', middleware.allowAdminOrModerator, galleryPhotoController.hide_gallery_photo);

/* Update an specific gallery photo */
router.put('/update/:id', middleware.allowAdminOrModerator, galleryPhotoController.update_gallery_photo);

/* Delete gallery photo */
router.delete('/delete/:id', middleware.allowAdminOrModerator, galleryPhotoController.delete_gallery_photo);

module.exports = router;
