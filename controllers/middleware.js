const jwt = require('jsonwebtoken');
const BlacklistedTokenSchema = require('../models/backlistedToken');

/* Check if token is valid
 * If token is valid, call next()
 * If token is invalid, return 401 HTTP status code (Unauthorized)
 *
 * Function to protect routes
*/
exports.checkToken = async (req, res, next) => {
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
        return res.status(401).json({ 
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
            if (err.name === 'TokenExpiredError' && decodedJWT.payload.exp + 300000 >= (Date.now()/1000)) {
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
                res.status(401).json({ 
                    message: 'Autentication failed.', 
                    error: err.message 
                });
            }
        } else {
            // Continue with the request
            next();
        }
    });
}

exports.isAdmin = (req, res, next) => {

}

exports.isAdminOrCurrentUser = (req, res, next) => {

}

exports.isModerator = (req, res, next) => {

}

exports.isModeratorOrCurrentUser = (req, res, next) => {

}

exports.isAdminOrModerator = (req, res, next) => {
    
}

exports.isAdminOrModeratorOrCurrentUser = (req, res, next) => {

}

/* Refresh JWT token when it is expired by 5 minutes (max 5 minutes of inactivity) 
 * Middleware specially thought for no protected routes with autenticated users
*/
exports.refreshToken = async (req, res, next) => {
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
        if (err) {
            // --------------------------------------------------
            // Handle when JWT token is expired or invalid
            // --------------------------------------------------

            // Decode JWT token
            const decodedJWT = jwt.decode(req.token, { complete: true });
                
            // If JWT is expired refresh token if it is expired by 5 minutes (max 5 minutes of inactivity)
            if (err.name === 'TokenExpiredError' && decodedJWT.payload.exp + 300000 >= (Date.now()/1000)) {
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
                // Continue with the request (JWT token is invalid or has expired more than 5 minutes)
                return next();
            }
        } else {
            // Continue with the request
            return next();
        }
    });
}

