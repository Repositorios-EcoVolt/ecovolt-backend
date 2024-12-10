const asyncHandler = require('express-async-handler');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const passport = require('passport');
const jwt = require('jsonwebtoken');

const UserSchema = require('../models/user');
const MessageSchema = require('../models/message');

// Protected route (EXAMPLE)
exports.index_get = asyncHandler(async (req, res, next) => {
    console.log(`${req.method} ${req.originalUrl} ${req.statusCode}`);

   
    res.render('index', 
    { 
        title: 'Message Board',
        user: authorizedData,
        isUserLoggedIn: true, 
    });
});

// Healty check route
exports.health_check = asyncHandler(async (req, res, next) => {
    console.log(`${req.method} ${req.originalUrl} ${req.statusCode}`);
    res.setHeader('Content-Type', 'application/json');
    res.status(200).send({ message: 'Server is running' });
});
