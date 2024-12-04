const asyncHandler = require('express-async-handler');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const passport = require('passport');

const logger = require('./logger');
const MessageSchema = require('./models/message');

exports.index_get = asyncHandler(async (req, res, next) => {
    logger.info(`${req.method} ${req.originalUrl} ${req.statusCode}`);

    // Query to MongoDB
    // const messages = await MessageSchema.find({ deleted: false })
    //     .sort({ created_at: -1 })
    //     .populate("user")
    //     .exec();

    res.render('index', 
        { 
            title: 'Message Board',
            user: res.locals.currentUser,
            isUserLoggedIn: !!res.locals.currentUser, 
        });
});


exports.user_create_get = asyncHandler(function (req, res, next) {
    logger.info(`${req.method} ${req.originalUrl} ${res.statusCode}`);

    if(res.locals.currentUser) {
        res.redirect('/');
        return;
    } 

    logger.info('User registration form');

    res.render("signup", {
        title: "Sign Up",
        user: null,
        isUserLoggedIn: false,
        newUser: {
            first_name: "",
            last_name: "",
            email: ""
        },
        errors: []
    });
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
        logger.info(`${req.method} ${req.originalUrl} ${res.statusCode}`);

        const errors = validationResult(req);

        const { first_name, last_name, email, password } = req.body;

        if (!errors.isEmpty()) {
            res.render('signup', {
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
                res.redirect('/login?');
            });
        } catch (err) {
            return next(err);
        }
    })
]