var express = require('express');
var router = express.Router();

const donationController = require('../controllers/donationsController');
const middleware = require('../controllers/middleware');

router.post('/', middleware.allowAny, donationController.create_donation);

module.exports = router;