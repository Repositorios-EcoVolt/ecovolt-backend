const { body, validationResult } = require('express-validator');

const asyncHandler = require('express-async-handler');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const user = require('../models/user');

const UserSchema = require('../models/user');
const BlacklistedTokenSchema = require('../models/backlistedToken');


exports.create_user = [
    // Fields
    body('username', 'Username must not be empty.').trim().isLength({ min: 1 }).escape(),
    body('first_name', 'First name must not be empty.').trim().isLength({ min: 1 }).escape(),
    body('last_name', 'Last name must not be empty.').trim().isLength({ min: 1 }).escape(),
    body('email', 'Email must not be empty.').trim().isLength({ min: 1 }).escape(),
    body('password', 'Password must not be empty.').trim().isLength({ min: 1 }).escape(),
    body('roles', 'Roles must not be empty.').trim().isLength({ min: 1 }).escape(),

    // Validators 
    body('username').custom(async (value) => {
        const usernameExists = await UserSchema.exists({ username: value });

        if (usernameExists) {
            throw new Error('Username already exists.');
        }
        return true;
    }),

    body('email').isEmail().withMessage('Invalid email address.').normalizeEmail(),

    body('password').custom(async (value) => {
        if (!value.match(/[A-Z]/))
            throw new Error('Password must contain at least one uppercase letter.');

        if (!value.match(/[a-z]/))
            throw new Error('Password must contain at least one lowercase letter.');

        if (!value.match(/[0-9]/))
            throw new Error('Password must contain at least one number.');
        
        if (!value.match(/[!@#$%^&*]/))
            throw new Error('Password must contain at least one special character.');

        if(value.length < 12)
            throw new Error('Password must be at least 12 characters long.');

        if (value.includes(req.body.username)) {
            throw new Error('Password must not contain the username.');
        }
        
        if (value.includes(req.body.first_name)) {
            throw new Error('Password must not contain the first name.');
        }

        if (value.includes(req.body.last_name)) {
            throw new Error('Password must not contain the last name.');
        }

        if (value.includes(req.body.email)) {
            throw new Error('Password must not contain the email.');
        }

        // TO DO: Add more common passwords using MongoDB database
        const commonPasswords = ['1230', 'password']

        if (commonPasswords.includes(value)) {
            throw new Error('Password is too common.');
        }
        
        return true;
    }),
    
    body('roles').custom(async (value) => {
        const roles = ['admin', 'moderator', 'member'];

        if (!roles.includes(value)) {
            throw new Error('Invalid role.\n The only valid roles are: "admin", "moderator" and "member".');
        }

        return true;
    }),

    // Main function
    asyncHandler(async function (req, res, next) {
        res.setHeader('Content-Type', 'application/json');

        const errors = validationResult(req);
        const { password } = req.body;

        if (!errors.isEmpty())
            return res.status(400).send({
                details: errors.array()
            });

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
                    last_login: null,
                    verified: false
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
                    verified: user.verified
                });
            });
        } catch (err) {
            res.send({
                detail: err.message
            });
        }
    })
]


exports.get_user = asyncHandler(async function (req, res, next) {
    res.setHeader('Content-Type', 'application/json');

    // Get JWT token (bearer) from authorization header
    const header = req.headers['authorization'];
    let token = null;
    
    if (typeof header !== 'undefined') {
        // Extract token from header
        const bearer = header.split(' ');
        token = bearer[1];
    } else {
        // Extract token from cookie
        if(req.cookies['JWT_token'])
            token = req.cookies['JWT_token'];
        else 
            // JWT token not provided
            return res.status(200).send({user: 'Anonymous user.'});
    }

    req.token = token;

    // Check if token is blacklisted
    const blacklistedToken = await BlacklistedTokenSchema.findOne({ token: token });

    // JWT token is blacklisted
    if (blacklistedToken)
        return res.status(200).send({user: 'Anonymous user.'});

    // Verify if a user is logged in through JWT token
    jwt.verify(req.token, process.env.JWT_SECRET, async (err, authorizedData) => {
        if (err) {
            // --------------------------------------------------
            // Handle when JWT token is expired or invalid
            // --------------------------------------------------
            
            // Decode JWT token
            const decodedJWT = jwt.decode(req.token, { complete: true });

            // If JWT is expired refresh token if it is expired by 5 minutes (max 5 minutes of inactivity)
            if (err.name === 'TokenExpiredError' && decodedJWT.payload.exp + 300 >= (Date.now()/1000)) {
                // Blacklist previous token
                const blacklistedToken = new BlacklistedTokenSchema({ 
                    token: req.token,
                    expire_at: new Date().setTime((decodedJWT.payload.exp * 1000) + 300000)
                });

                // Save blacklisted token in database
                await blacklistedToken.save();

                // Refresh JWT token
                const userDTO = decodedJWT.payload.userDTO;
                const token = jwt.sign({ userDTO }, process.env.JWT_SECRET, { expiresIn: 300 });
            
                // Erase previous cookie
                res.clearCookie('JWT_token');
            
                // Set token in cookie
                res.cookie('JWT_token', token, { httpOnly: true });            
 
            } else {
                // No valid JWT token
                return res.status(200).send({user: 'Anonymous user.'});
            } 
        } 

        // Decode JWT token
        const decodedJWT = jwt.decode(req.token, { complete: true });

        // Get current user
        const currentUser = decodedJWT.payload.userDTO;
                
        // Return user data (DTO)
        return res.status(200).send(currentUser);
        
    });
});


exports.get_user_by_id = asyncHandler(async function (req, res, next) {
    res.setHeader('Content-Type', 'application/json');

    // Get user object
    const userFound = await UserSchema.findById(req.params.id);

    // Check if user exists
    if (!userFound) 
        return res.status(404).send({
            detail: 'User not found.'
        });

    // Get JWT token (bearer) from authorization header
    const header = req.headers['authorization'];
    let token = null;

    if (typeof header !== 'undefined') {
        // Extract token from header
        const bearer = header.split(' ');
        token = bearer[1];
    } else {
        // Extract token from cookie
        if(req.cookies['JWT_token'])
            token = req.cookies['JWT_token'];
        else 
            // JWT token not provided
            return res.status(200).send({
                username: userFound.username,
                first_name: userFound.first_name,
                last_name: userFound.last_name
            });
    }

    req.token = token;

    // Check if token is blacklisted
    const blacklistedToken = await BlacklistedTokenSchema.findOne({ token: token});

    // If JWT token is blacklisted
    if (blacklistedToken)
        return res.status(200).send({
            username: userFound.username,
            first_name: userFound.first_name,
            last_name: userFound.last_name
        });

    // Verify if a user is logged in through JWT token
    jwt.verify(req.token, process.env.JWT_SECRET, async (err, authorizedData) => {
        if (err) {
            // --------------------------------------------------
            // Handle when JWT token is expired or invalid
            // --------------------------------------------------
            
            // Decode JWT token
            const decodedJWT = jwt.decode(req.token, { complete: true });

            // If JWT is expired refresh token if it is expired by 5 minutes (max 5 minutes of inactivity)
            if (err.name === 'TokenExpiredError' && decodedJWT.payload.exp + 300 >= (Date.now()/1000)) {
                // Blacklist previous token
                const blacklistedToken = new BlacklistedTokenSchema({ 
                    token: req.token,
                    expire_at: new Date().setTime((decodedJWT.payload.exp * 1000) + 300000)
                });

                // Save blacklisted token in database
                await blacklistedToken.save();

                // Refresh JWT token
                const userDTO = decodedJWT.payload.userDTO;
                const token = jwt.sign({ userDTO }, process.env.JWT_SECRET, { expiresIn: 300 });
            
                // Erase previous cookie
                res.clearCookie('JWT_token');
            
                // Set token in cookie
                res.cookie('JWT_token', token, { httpOnly: true });            
 
            } else {
                // No valid JWT token
                return res.status(200).send({
                    username: userFound.username,
                    first_name: userFound.first_name,
                    last_name: userFound.last_name
                });
            } 
        }
    });

    // Return user data (DTO)
    res.status(200).send({
        id: userFound._id,
        username: userFound.username,
        first_name: userFound.first_name,
        last_name: userFound.last_name,
        email: userFound.email,
        roles: userFound.roles,
        created_at: userFound.created_at,
        updated_at: userFound.updated_at,
        last_login: userFound.last_login
    });
});

/* Update user only if the user is the same that will be updated or it's admin */
exports.update_user = asyncHandler(async function (req, res, next) {
    res.setHeader('Content-Type', 'application/json');

    // Possible fields to update
    if (req.body.username){
        body('username', 'Username must not be empty.').trim().isLength({ min: 1 }).escape();

        body('username').custom(async (value) => {
            const usernameExists = await UserSchema.exists( { username: value });
            const currentUsername = await UserSchema.findById(req.params.id);
        
            if (usernameExists && currentUsername.username !== value) 
                throw new Error('Username already exists.');
    
            return true        
        });
    }

    if (req.body.first_name)
        body('first_name', 'First name must not be empty.').trim().isLength({ min: 1 }).escape();

    if (req.body.last_name)
        body('last_name', 'Last name must not be empty.').trim().isLength({ min: 1 }).escape();

    if (req.body.email){
        body('email', 'Email must not be empty.').trim().isLength({ min: 1 }).escape();
        body('email').isEmail().withMessage('Invalid email address.').normalizeEmail();
    }

    try{
        // Get JWT token (bearer) from authorization header
        const header = req.headers['authorization'];
        let token = null;

        // Extract token from either header or cookie
        if (typeof header !== 'undefined') {
            // Extract token from header
            const bearer = header.split(' ');
            token = bearer[1];
        } else {
            // Extract token from cookie
            if(req.cookies['JWT_token']){
                token = req.cookies['JWT_token'];
            } else {
                // JWT token not provided
                return res.status(401).send({
                    detail: 'Unauthorized.'
                });
            }
        }

        req.token = token;

        // Check if the token is blacklisted
        const blacklistedToken = await BlacklistedTokenSchema.findOne({ token: token });

        // If JWT token is blacklisted
        if (blacklistedToken)
            return res.status(401).send({
                detail: 'Unauthorized.'
            });

        jwt.verify(req.token, process.env.JWT_SECRET, async (err, authorizedData) => {
            // Decode JWT token
            const decodedJWT = jwt.decode(req.token, { complete: true });

            if (err) {
                // --------------------------------------------------
                // Handle when JWT token is expired or invalid
                // --------------------------------------------------                

                // If JWT has expired more than 5 minutes
                if (!(err.name === 'TokenExpiredError' && decodedJWT.payload.exp + 300 >= (Date.now()/1000)))
                    return res.status(401).send({
                        detail: 'Unauthorized.'
                    });

                // --------------------------------------------------
                // If the token has expired in the last 5 minutes
                // --------------------------------------------------

                // Blacklist previous token
                const blacklistedToken = new BlacklistedTokenSchema({
                    token: req.token,
                    expire_at: new Date().setTime((decodedJWT.payload.exp * 1000) + 300000)
                });

                // Save blacklisted token in database
                await blacklistedToken.save();

                // Refresh JWT token
                const userDTO = decodedJWT.payload.userDTO;
                const newToken = jwt.sign({ userDTO }, process.env.JWT_SECRET, { expiresIn: 300 });

                // Erase previous cookie
                res.clearCookie('JWT_token');

                // Set token in 'JWT_token' cookie
                res.cookie('JWT_token', newToken, { httpOnly: true, secure: true });   
    
            } 

            // Check if the user is the same that will be updated or it's admin
            if(decodedJWT.payload.userDTO.id != req.params.id && !decodedJWT.payload.userDTO.roles.includes('admin'))
                return res.status(401).send({
                    detail: 'Unauthorized.'
                });
                
            // Get previous user information
            const userFound = await UserSchema.findById(req.params.id);

            // Check if user exists
            if(!userFound)
                return res.status(404).send({
                    detail: 'User not found.'
                });

            // If the user is admin, it can update the active and roles fields
            if (decodedJWT.payload.userDTO.roles.includes('admin')) {
                // Other fields for admin
                body('roles', 'Roles must not be empty.').trim().isLength({ min: 1 }).escape();
                body('active').isBoolean().withMessage('Active must be either "true" or "false".');

                // Other validators for admin
                body('roles').custom(async (value) => {
                    const roles = ['admin', 'moderator', 'member'];

                    if (!roles.includes(value)) 
                        throw new Error('Invalid role.\n The only valid roles are: "admin", "moderator" and "member".');
                    
                    return true;
                });

                // Catch validation errors (if any)
                const errors = validationResult(req);

                // If there are errors, return them
                if (!errors.isEmpty())
                    return res.status(400).send({
                        details: errors.array()
                    });

                // Update user 
                const updatedUser = await UserSchema.findByIdAndUpdate(req.params.id, {
                    username: req.body.username? req.body.username:userFound.username,
                    first_name: req.body.first_name? req.body.first_name:userFound.first_name,
                    last_name: req.body.last_name? req.body.last_name:userFound.last_name,
                    email: req.body.email? req.body.email:userFound.email,
                    roles: req.body.roles? req.body.roles:userFound.roles,
                    active: req.body.active? req.body.active:userFound.active,
                    updated_at: new Date()
                }, { new: true });

                // If the information was not updated send 304 status code
                if (updatedUser.username === userFound.username && 
                    updatedUser.first_name === userFound.first_name && 
                    updatedUser.last_name === userFound.last_name && 
                    updatedUser.email === userFound.email && 
                    updatedUser.roles[0] === userFound.roles[0] && 
                    updatedUser.active === userFound.active)
                    return res.status(304).send();

                // Return user data (DTO)
                return res.status(200).send({
                    id: updatedUser._id,
                    username: updatedUser.username,
                    first_name: updatedUser.first_name,
                    last_name: updatedUser.last_name,
                    email: updatedUser.email,
                    roles: updatedUser.roles,
                    created_at: updatedUser.created_at,
                    updated_at: updatedUser.updated_at,
                    last_login: updatedUser.last_login,
                    verified: updatedUser.verified,
                    active: updatedUser.active
                });

            } else {
                // Catch validation errors (if any)
                const errors = validationResult(req);

                // If there are errors, return them
                if (!errors.isEmpty())
                    return res.status(400).send({
                        details: errors.array()
                    });

                // If the user is not admin but it's the same user that will be updated
                const updatedUser = await UserSchema.findByIdAndUpdate(req.params.id, {
                    username: req.body.username? req.body.username:userFound.username,
                    first_name: req.body.first_name? req.body.first_name:userFound.first_name,
                    last_name: req.body.last_name? req.body.last_name:userFound.last_name,
                    email: req.body.email? req.body.email:userFound.email,
                    updated_at: new Date()
                }, { new: true });

                // If the information was not update send 304 status code
                if (updatedUser.username === userFound.username &&
                    updatedUser.first_name === userFound.first_name &&
                    updatedUser.last_name === userFound.last_name &&
                    updatedUser.email === userFound.email)
                    return res.status(304).send();

                // Return user data (DTO)
                return res.status(200).send({
                    id: updatedUser._id,
                    username: updatedUser.username,
                    first_name: updatedUser.first_name,
                    last_name: updatedUser.last_name,
                    email: updatedUser.email,
                    roles: updatedUser.roles,
                    created_at: updatedUser.created_at,
                    updated_at: updatedUser.updated_at,
                    last_login: updatedUser.last_login
                });
            }
        });
        
    } catch (err) {
        return res.status(500).send({
            detail: err.message
        });
    }    
});


exports.update_user_password = [
    // Fields
    body('password', 'Password must not be empty.').trim().isLength({ min: 1}).escape(),

    // Validators
    body('password').custom(async (value) => {
        if (!value.match(/[A-Z]/))
            throw new Error('Password must contain at least one uppercase letter.');

        if (!value.match(/[a-z]/))
            throw new Error('Password must contain at least one lowercase letter.');

        if (!value.match(/[0-9]/))
            throw new Error('Password must contain at least one number.');
        
        if (!value.match(/[!@#$%^&*()-_=+\\|\[\]{};:?.><]/))
            throw new Error('Password must contain at least one special character.');

        if(value.length < 12)
            throw new Error('Password must be at least 12 characters long.');

        // TO DO: Add more common passwords using MongoDB database
        const commonPasswords = ['1230', 'password']

        if (commonPasswords.includes(value)) {
            throw new Error('Password is too common.');
        }
        
        return true;
    }), 

    // Main function
    asyncHandler(async function (req, res, next) {
        res.header('Content-Type', 'application/json');

        try {
            // Verify if the user is admin of it's the same user that will be updated
            const header = req.headers['authorization'];
            let token = null;

            // Extract token from either header or cookie
            if (typeof header !== 'undefined') {
                // Extract token from header
                const bearer = header.split(' ');
                token = bearer[1];
            } else {
                // Extract token from cookie
                if(req.cookies['JWT_token']){
                    token = req.cookies['JWT_token'];
                } else {
                    // JWT token not provided
                    return res.status(401).send({
                        detail: 'Unauthorized.'
                    });
                }
            }

            req.token = token;

            // Check if the token is blacklisted
            const blacklistedToken = await BlacklistedTokenSchema.findOne({ token: token });

            // If JWT token is blacklisted
            if (blacklistedToken)
                return res.status(401).send({
                    detail: 'Unauthorized.'
                });

            jwt.verify(req.token, process.env.JWT_SECRET, async (err, authorizedData) => {
                // Decode JWT token
                const decodedJWT = jwt.decode(req.token, { complete: true });

                if (err) {
                    // --------------------------------------------------
                    // Handle when JWT token is expired or invalid
                    // --------------------------------------------------                

                    // If JWT has expired more than 5 minutes
                    if (!(err.name === 'TokenExpiredError' && decodedJWT.payload.exp + 300 >= (Date.now()/1000)))
                        return res.status(401).send({
                            detail: 'Unauthorized.'
                        });

                    // --------------------------------------------------
                    // If the token has expired in the last 5 minutes
                    // --------------------------------------------------

                    // Blacklist previous token
                    const blacklistedToken = new BlacklistedTokenSchema({
                        token: req.token,
                        expire_at: new Date().setTime((decodedJWT.payload.exp * 1000) + 300000)
                    });

                    // Save blacklisted token in database
                    await blacklistedToken.save();

                    // Refresh JWT token
                    const userDTO = decodedJWT.payload.userDTO;
                    const newToken = jwt.sign({ userDTO }, process.env.JWT_SECRET, { expiresIn: 300 });

                    // Erase previous cookie
                    res.clearCookie('JWT_token');

                    // Set token in 'JWT_token' cookie
                    res.cookie('JWT_token', newToken, { httpOnly: true, secure: true });   
                }

                // Check if the user is the same that will be updated or it's admin
                if(decodedJWT.payload.userDTO.id != req.params.id && !decodedJWT.payload.userDTO.roles.includes('admin'))
                    return res.status(401).send({
                        detail: 'Unauthorized.'
                    });

                // Get previous user information
                const userFound = await UserSchema.findById(req.params.id);
                
                // Check if user exists
                if(!userFound)
                    return res.status(404).send({
                        detail: 'User not found.'
                    });

                // Check for old password if the user is the same that will be updated
                if (decodedJWT.payload.userDTO.id == req.params.id)
                    // Check if the password is the same as the previous one
                    bcrypt.compare(req.body.old_password, userFound.password, async (err, result) => {
                        // If the password is not the same that the previous one or other errors
                        if (!result || err)
                            return res.status(401).send({
                                detail: 'Unauthorized.'
                            });
                    });
                
                // Check if the password is the same as the previous one
                bcrypt.compare(req.body.password, userFound.password, async (err, result) => {
                    if (result) {
                        return res.status(304).send();
                    } else {
                        // Validators 
                        body('password').custom(async (value) => {
                            if (value.includes(userFound.username))
                                return res.status(400).send({
                                    detail: 'Password must not contain the username.'
                                });

                            if (value.includes(userFound.first_name))
                                return res.status(400).send({
                                    detail: 'Password must not contain the first name.'
                                });
        
                            if (value.includes(userFound.last_name))
                                return res.status(400).send({
                                    detail: 'Password must not contain the last name.'
                                });
        
                            if (value.includes(userFound.email))
                                return res.status(400).send({
                                    detail: 'Password must not contain the email.'
                                });
        
                            // TO DO: Add more common passwords using MongoDB database
                            const commonPasswords = ['1230', 'password']
        
                            if (commonPasswords.includes(req.body.password))
                                return res.status(400).send({
                                    detail: 'Password is too common.'
                                });

                            return true;
                        }); 

                        // Catch validation errors (if any)
                        const errors = validationResult(req);

                        // If there are errors, return them
                        if (!errors.isEmpty())
                            return res.status(400).send({
                                details: errors.array()
                            });

                        // Password encryption
                        // Algorith: The Blowfish cipher algorithm (bcrypt)
                        // Rounds (salts): 10
                        bcrypt.hash(req.body.password, 10, async (err, hashedPassword) => {
                            if (err)
                                return res.status(500).send({
                                    details: err.message 
                                });
                            
                            // Update user password
                            const updatedUser = await UserSchema.findByIdAndUpdate(req.params.id, {
                                password: hashedPassword,
                                updated_at: new Date()
                            }, { new: true });

                            // Show success message
                            return res.status(200).send({
                                message: "Password for user '" + updatedUser.username + "' updated successfully.",
                            });
                        });
                    }
                });
            });

        } catch (err) {
            return res.status(500).send({
                details: err.message
            });
        }
        
    })
];


exports.get_users = asyncHandler(async function (req, res, next) {
    res.setHeader('Content-Type', 'application/json');

    try {
        const users = await user.find();

        const usersDTO = users.map((user) => {
            return {
                id: user._id,
                username: user.username,
                first_name: user.first_name,
                last_name: user.last_name,
                email: user.email,
                roles: user.roles,
                created_at: user.created_at,
                updated_at: user.updated_at,
                last_login: user.last_login
            }
        });

        res.status(200).send(usersDTO);
    } catch (err) {
        res.status(500).send({
            detail: err.message
        });
    }
});


exports.delete_user = asyncHandler(async function (req, res, next) {
    // Get username from URL
    const username = req.params['username'];

    // Get user object to delete
    const userToDelete = await user.findOne({ username: username });

    // Check if user exists
    if (!userToDelete) 
        return res.status(404).send({
            detail: 'User not found.'
        });

    // Delete user
    await userToDelete.deleteOne();

    // Return success message
    res.status(204).send();
});
