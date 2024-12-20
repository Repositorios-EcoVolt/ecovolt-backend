const asyncHandler = require('express-async-handler');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const passport = require('passport');
const jwt = require('jsonwebtoken');

const UserSchema = require('../models/user');
const MessageSchema = require('../models/message');

// Healty check route
exports.health_check = asyncHandler(async (req, res, next) => {
    res.setHeader('Content-Type', 'application/json');
    res.status(200).send({ message: 'Server is running (all services operational).' });
});
