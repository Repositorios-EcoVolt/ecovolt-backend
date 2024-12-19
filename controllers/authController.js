const asyncHandler = require('express-async-handler')
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const UserSchema = require('../models/user');
const BlacklistedTokenSchema = require('../models/backlistedToken');

exports.login = asyncHandler(async (req, res, next) => {
    res.setHeader('Content-Type', 'application/json');

    const { username, password } = req.body;

    try {
        const user = await UserSchema.findOne({ username: username });

        if (!user) {
            return res.status(401).json({ message: 'Invalid username or password.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid password or password.' });
        }

        // Modify last login attribute in database
        user.last_login = new Date();
        user.save();

        // Avoid the password attribute in the token
        const userDTO = {
            username: user.username,
            first_name: user.first_name,
            last_name: user.last_name,
            email: user.email,
            roles: user.roles,
            created_at: user.created_at,
            updated_at: user.updated_at,
            last_login: user.last_login
        }

        // Create JWT token encoded with the userDTO as bearer
        const token = jwt.sign({ userDTO }, process.env.JWT_SECRET, { expiresIn: 300 });

        // Set token in cookie
        res.cookie('JWT_token', token, { httpOnly: true });

        return res.status(200).json({ token: token });
    } catch (err) {
        return res.status(500).json({ message: 'Internal Server Error' });
    }
})


// TODO: Implement blacklist for tokens
exports.logout = asyncHandler(async (req, res, next) => {
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
            return res.status(200).json({ message: 'You are not logged in.' });
    }
    
    req.token = token;

    // Check if the token is blacklisted
    const isTokenBlacklisted = await BlacklistedTokenSchema.findOne({ token: token });

    // If the token is blacklisted, return a message that the user is already logged out
    if (isTokenBlacklisted) {
        return res.status(200).json({ message: 'You are not logged in.' });
    }

    // Verify if a user is logged in through JWT token
    jwt.verify(req.token, process.env.JWT_SECRET, async (err, authorizedData) => {
        // Decode JWT token
        const decodedJWT = jwt.decode(req.token, { complete: true });
            
        // If JWT is expired and can't be refreshed or it is invalid
        if (err && !(err.name === 'TokenExpiredError' && decodedJWT.payload.exp + 300000 >= (Date.now()/1000))) {
            return res.status(200).json({ message: 'You are not logged in.' });
        } else {
            // Decode JWT
            const decodedToken = jwt.decode(req.token);
                
            // Create new blacklisted token
            const blacklistedToken = new BlacklistedTokenSchema({
                token: req.token,
                expire_at: new Date().setTime((decodedToken.exp * 1000) + 300000)
            });

            // Save blacklisted token in database
            await blacklistedToken.save();

            // Erase cookie
            res.clearCookie('JWT_token');

            // Return success message
            return res.status(200).json({ message: 'Logout successful.' });
        }
    })
});
