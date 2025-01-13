// --------------------------------------------
// Multer configuration for uploading files
// --------------------------------------------

const multer = require('multer');

// Settings for the storage engine
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'public/images')
    },

    filename: (req, file, cb) => {
        cb(null, file.originalname)
    }
});

const upload = multer({ storage: storage});

module.exports = upload;
