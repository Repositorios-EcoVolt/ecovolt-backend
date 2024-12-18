const jwt = require('jsonwebtoken');
const BlacklistedTokenSchema = require('../models/backlistedToken');

/* Check if token is valid
 * If token is valid, call next()
 * If token is invalid, return 401 HTTP status code (Unauthorized)
 *
 * Function to protect routes
*/
exports.checkToken = (req, res, next) => {
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

    jwt.verify(req.token, process.env.JWT_SECRET, async (err, authorizedData) => {
        if (err) {
            // --------------------------------------------------
            // Handle when JWT token is expired or invalid
            // --------------------------------------------------

            // Decode JWT token
            const decodedJWT = jwt.decode(req.token, { complete: true });
                
            // If JWT is expired refresh token if it is expired by 5 minutes (max 5 minutes of inactivity)
            if (err.name === 'TokenExpiredError' && decodedJWT.exp + 300 < (Date.now()/1000)) {
                // Refresh JWT token
                const userDTO = decodedJWT.payload.userDTO;
                const token = jwt.sign({ userDTO }, process.env.JWT_SECRET, { expiresIn: '1h' });

                // Erase previous cookie
                res.clearCookie('JWT_token');

                // Set token in cookie
                res.cookie('JWT_token', token, { httpOnly: true });

                // Continue with the request
                next();
            }

            res.status(401).json({ 
                message: 'Autentication failed.', 
                error: err.message 
            });
        } else {
            // Check if the token is blacklisted
            const blacklistedToken = await BlacklistedTokenSchema.findOne({ token: token });

            // JWT token is blacklisted
            if (blacklistedToken) 
                return res.status(401).json({ 
                    message: 'Autentication failed.', 
                    error: 'jwt expired' 
                });
            else
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

