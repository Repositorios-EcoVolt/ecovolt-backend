const asyncHandler = require('express-async-handler')
const jwt = require('jsonwebtoken');
const UserSchema = require('../models/user');
const bcrypt = require('bcrypt');

exports.login = asyncHandler(async (req, res, next) => {
    console.log(`${req.method} ${req.originalUrl} ${req.statusCode}`);
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
        const token = jwt.sign({ userDTO }, process.env.JWT_SECRET, { expiresIn: '1h' });

        return res.status(200).json({ token: token });
    } catch (err) {
        return res.status(500).json({ message: 'Internal Server Error' });
    }
})

