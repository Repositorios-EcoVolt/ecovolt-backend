const { body, validationResult } = require('express-validator');
const asyncHandler = require('express-async-handler');
const bcrypt = require('bcrypt');
const UserSchema = require('../models/user');


exports.create_user = [
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
        res.setHeader('Content-Type', 'application/json');

        const errors = validationResult(req);
        const { first_name, last_name, email, password } = req.body;

        if (!errors.isEmpty()) {
            res.status(400).send({
                details: errors.array()
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

                // Create new user object
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

                // Save user in database
                await user.save();
                
                // Return user data (DTO)
                res.status(201).send({
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

exports.get_users = asyncHandler(function (req, res, next) {
    console.log(`${req.method} ${req.originalUrl} ${res.statusCode}`);
    res.setHeader('Content-Type', 'application/json');

    const users = UserSchema.find();
    res.send(users.find());
});