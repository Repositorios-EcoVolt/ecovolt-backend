var express = require('express');
var multer = require('multer');
var router = express.Router();

const informationController = require('../controllers/informationSectionController');
const middleware = require('../controllers/middleware');

// Settings for the storage engine
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadPath = 'public/images/';
        fs.mkdirSync(uploadPath, recursive = true);
        cb(null, uploadPath);

        req.file = file;
    },

    filename: (req, file, cb) => {
        cb(null, file.originalname)
    }
});

// Multer configuration for uploading files
const upload = multer({ 
    storage: storage,
    limits: {
        fileSize: 1024 * 1024 * 5
    },
    fileFilter: (req, file, cb) => {
        const allowedMimeTypes = ['image/jpeg', 'image/png', 'image/jpg', 'image/svg+xml', 'image/gif'];

        if(allowedMimeTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only JPEG, PNG, SVG and GIF image files are allowed.'));
        }
    }
});

/* Show all information sections */
router.get('/', middleware.allowAny, informationController.get_information_sections);

/* Add new information section */
router.post('/add', middleware.allowAdminOrModerator, informationController.add_information_section);

/* Add picture for an information section */
router.post('/add-picture/:id', middleware.allowAdminOrModerator, informationController.add_information_section_picture);

/* Publish information section */
router.patch('/publish/:id', middleware.allowAdminOrModerator, informationController.publish_information_section);

/* Unpublish information section */
router.patch('/unpublish/:id', middleware.allowAdminOrModerator, informationController.hide_information_section);

/* Update information section */
router.put('/update/:id', middleware.allowAdminOrModerator, informationController.update_information_section);

/* Remove picture for an information section */
router.delete('/remove-picture/:id', middleware.allowAdminOrModerator, informationController.remove_information_section_picture);

/* Delete information section */
router.delete('/delete/:id', middleware.allowAdminOrModerator, informationController.delete_information_section);

module.exports = router;
