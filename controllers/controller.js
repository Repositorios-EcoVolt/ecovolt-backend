const asyncHandler = require('express-async-handler');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const passport = require('passport');
const jwt = require('jsonwebtoken');

const UserSchema = require('../models/user');
const MessageSchema = require('../models/message');

// Protected route
exports.index_get = asyncHandler(async (req, res, next) => {
    console.log(`${req.method} ${req.originalUrl} ${req.statusCode}`);

    // Query to MongoDB
    // const messages = await MessageSchema.find({ deleted: false })
    //     .sort({ created_at: -1 })
    //     .populate("user")
    //     .exec();

    jwt.verify(req.token, process.env.JWT_SECRET, (err, authorizedData) => {
        if (err) {
            res.status(403).json({ 
                message: 'Autentication credentials were not provided.',
                error: err.message
             });

        } else {
            res.render('index', 
                { 
                    title: 'Message Board',
                    user: authorizedData,
                    isUserLoggedIn: true, 
                });
        }
    });

});


exports.get_users = asyncHandler(function (req, res, next) {
    console.log(`${req.method} ${req.originalUrl} ${res.statusCode}`);
    res.setHeader('Content-Type', 'application/json');

    res.send({
        title: 'Sign Up',
        user:  null,
        isUserLoggedIn: res.body.currentUser !== null,
        newUser: {
            first_name: '',
            last_name: '',
            email: ''
        },
        errors: []
    })

    // res.render("signup", {
    //     title: "Sign Up",
    //     user: null,
    //     isUserLoggedIn: false,
    //     newUser: {
    //         first_name: "",
    //         last_name: "",
    //         email: ""
    //     },
    //     errors: []
    // });
});

exports.user_create_post = [
    // Fields
    body('username', 'Username must not be empty.').trim().isLength({ min: 1 }).escape(),
    body('first_name', 'First name must not be empty.').trim().isLength({ min: 1 }).escape(),
    body('last_name', 'Last name must not be empty.').trim().isLength({ min: 1 }).escape(),
    body('email', 'Email must not be empty.').trim().isLength({ min: 1 }).escape(),
    body('password', 'Password must not be empty.').trim().isLength({ min: 1 }).escape(),
    body('role', 'Role must not be empty.').trim().isLength({ min: 1 }).escape(),

    // Validators 
    body('username').custom(async (value) => {
        const usernameExists = await UserSchema.exists({ username: value });

        if (usernameExists) {
            throw new Error('Username already exists.');
        }
        return true;
    }),

    // Main function
    asyncHandler(async function (req, res, next) {
        console.log(`${req.method} ${req.originalUrl} ${res.statusCode}`);

        const errors = validationResult(req);

        const { first_name, last_name, email, password } = req.body;
        res.setHeader('Content-Type', 'application/json');

        if (!errors.isEmpty()) {
            res.send({
                title: 'Sign Up',
                user: null,
                isUserLoggedIn: false,
                newUser: {
                    first_name,
                    last_name,
                    email
                },
                errors: errors.array()
            });
            return;
        }

        // Password encryption
        // Algorith: The Blowfish cipher algorithm (bcrypt)
        // Rounds (salts): 10
        try {
            bcrypt.hash(password, 10, async (err, hashedPassword) => {
                if (err) {
                    return next(err);
                }

                const user = new UserSchema({
                    username: req.body.username,
                    first_name: req.body.first_name,
                    last_name: req.body.last_name,
                    email: req.body.email,
                    password: hashedPassword,
                    roles: [req.body.role],
                    created_at: new Date(),
                    updated_at: null,
                    last_login: null
                })

                await user.save();
                res.send({
                    username: user.username,
                    first_name: user.first_name,
                    last_name: user.last_name,
                    email: user.email,
                    roles: user.roles,
                    created_at: user.created_at,
                });
            });
        } catch (err) {
            res.send({
                detail: err.message
            });
        }
    })
]
