const jwt = require('jsonwebtoken');
const csrf = require('csurf');
const BlacklistedTokenSchema = require('../models/backlistedToken');

const multer = require('multer');
const path = require('path');
const fs = require('fs');

exports.csrfProtect = csrf({ cookie: true });

exports.allowAdmin = async (req, res, next) => {
    // Get JWT token (bearer) from authorization header
    const header = req.headers['authorization'];
    let token = null;

    // Extract either token from header or cookie
    if (typeof header !== 'undefined') {
        // Extract token from header
        const bearer = header.split(' ');
        token = bearer[1];
    } else {
        // Extract token from cookie
        if(req.cookies['JWT_token'])
            token = req.cookies['JWT_token'];
        else
            return res.status(401).json({ message: 'Authentication credentials were not provided' });
    }

    req.token = token;

    // Check if the token is blacklisted
    const blacklistedToken = await BlacklistedTokenSchema.findOne({ token: token });

    // JWT token is blacklisted
    if (blacklistedToken) 
        return res.status(498).json({ 
            message: 'Autentication failed.', 
            error: 'jwt expired' 
        });

    jwt.verify(req.token, process.env.JWT_SECRET, async (err, authorizedData) => {
        if (err) {
            // --------------------------------------------------
            // Handle when JWT token is expired or invalid
            // --------------------------------------------------

            // Decode JWT token
            const decodedJWT = jwt.decode(req.token, { complete: true });

            // User data
            const userDTO = decodedJWT.payload.userDTO;
                
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
                const token = jwt.sign({ userDTO }, process.env.JWT_SECRET, { expiresIn: 300 });

                // Erase previous cookie
                res.clearCookie('JWT_token');

                // Set token in cookie
                res.cookie('JWT_token', token, { httpOnly: true });

                // Check if user is admin
                if (userDTO.roles[0] === 'admin')
                    return next();
                else
                    return res.status(403).json({ message: 'The user has not enough privilegies' });
            } else {
                // JWT token is invalid or has expired more than 5 minutes
                return res.status(498).json({ 
                    message: 'Autentication failed.', 
                    error: err.message 
                });
            }
        } else {
            // Check if user is admin
            if (userDTO.roles[0] === 'admin')
                return next();
            else
                return res.status(403).json({ message: 'The user has not enough privilegies' });
        }
    });    
}

exports.allowAdminOrModerator = async (req, res, next) => {
    // Get JWT token (bearer) from authorization header
    const header = req.headers['authorization'];
    let token = null;

    // Extract either token from header or cookie
    if (typeof header !== 'undefined') {
        // Extract token from header
        const bearer = header.split(' ');
        token = bearer[1];
    } else {
        // Extract token from cookie
        if(req.cookies['JWT_token'])
            token = req.cookies['JWT_token'];
        else
            return res.status(401).json({ message: 'Authentication credentials were not provided' });
    }

    req.token = token;

    // Check if the token is blacklisted
    const blacklistedToken = await BlacklistedTokenSchema.findOne({ token: token });

    // JWT token is blacklisted
    if (blacklistedToken) 
        return res.status(498).json({ 
            message: 'Autentication failed.', 
            error: 'jwt expired' 
        });

    jwt.verify(req.token, process.env.JWT_SECRET, async (err, authorizedData) => {
        // Decode JWT token
        const decodedJWT = jwt.decode(req.token, { complete: true });
        const userDTO = decodedJWT.payload.userDTO;

        if (err) {
            // --------------------------------------------------
            // Handle when JWT token is expired or invalid
            // --------------------------------------------------
                
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
                const token = jwt.sign({ userDTO }, process.env.JWT_SECRET, { expiresIn: 300 });

                // Erase previous cookie
                res.clearCookie('JWT_token');

                // Set token in cookie
                res.cookie('JWT_token', token, { httpOnly: true });

                // Check if user is admin or moderator
                if (userDTO.roles[0] === 'admin' || userDTO.roles[0] === 'moderator')
                    return next();
                else
                    return res.status(403).json({ message: 'The user has not enough privilegies' });
            } else {
                // JWT token is invalid or has expired more than 5 minutes
                return res.status(498).json({ 
                    message: 'Autentication failed.', 
                    error: err.message 
                });
            }
        } else {
            // Check if user is admin or moderator
            if (userDTO.roles[0] === 'admin' || userDTO.roles[0] === 'moderator')
                return next();
            else
                return res.status(403).json({ message: 'The user has not enough privilegies' });
        }
    });    
}

/* Check if token is valid
 * If token is valid, call next()
 * If token is invalid, return 401 HTTP status code (Unauthorized)
 *
 * Function to protect routes
*/

exports.allowAuthenticated = async (req, res, next) => {
    // Get JWT token (bearer) from authorization header
    const header = req.headers['authorization'];
    let token = null;

    // Extract either token from header or cookie
    if (typeof header !== 'undefined') {
        // Extract token from header
        const bearer = header.split(' ');
        token = bearer[1];
    } else {
        // Extract token from cookie
        if(req.cookies['JWT_token'])
            token = req.cookies['JWT_token'];
        else
            return res.status(401).json({ message: 'Authentication credentials were not provided' });
    }

    req.token = token;

    // Check if the token is blacklisted
    const blacklistedToken = await BlacklistedTokenSchema.findOne({ token: token });

    // JWT token is blacklisted
    if (blacklistedToken) 
        return res.status(498).json({ 
            message: 'Autentication failed.', 
            error: 'jwt expired' 
        });

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

                // Continue with the request
                return next();
            } else {
                // JWT token is invalid or has expired more than 5 minutes
                return res.status(498).json({ 
                    message: 'Autentication failed.', 
                    error: err.message 
                });
            }
        } else {
            // Continue with the request
            return next();
        }
    });
}

/* Refresh JWT token when it is expired by 5 minutes (max 5 minutes of inactivity) 
 * Middleware specially thought for no protected routes with autenticated users
*/
exports.allowAny = async (req, res, next) => {
    // Get JWT token (bearer) from authorization header
    const header = req.headers['authorization'];
    let token = null;

    // Extract either token from header or cookie
    if (typeof header !== 'undefined') {
        // Extract token from header
        const bearer = header.split(' ');
        token = bearer[1];
    } else {
        // Extract token from cookie
        if(req.cookies['JWT_token'])
            token = req.cookies['JWT_token'];
        else
            return next(); 
    }

    req.token = token;

    // Check if the token is blacklisted
    const blacklistedToken = await BlacklistedTokenSchema.findOne({ token: token });

    // JWT token is blacklisted
    if (blacklistedToken) 
        return next();

    jwt.verify(req.token, process.env.JWT_SECRET, async (err, authorizedData) => {
        // Decode JWT token
        const decodedJWT = jwt.decode(req.token, { complete: true });

        // --------------------------------------------------
        // Handle when JWT token is expired or invalid
        // --------------------------------------------------

        // If JWT is expired refresh token if it is expired by 5 minutes (max 5 minutes of inactivity)
        if (err && !(err.name === 'TokenExpiredError' && decodedJWT.payload.exp + 300 >= (Date.now()/1000))) {
            
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
        }
    
        // Continue with the request (JWT token is invalid or has expired more than 5 minutes)
        return next();
        
    });
}


/* Action confirmation for dangerous actions */
