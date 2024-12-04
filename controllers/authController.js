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
            return res.status(401).json({ message: 'Invalid username or password.' });
        }

        const token = jwt.sign({ user }, process.env.JWT_SECRET, { expiresIn: '1h' });

        return res.status(200).json({ token });
    } catch (err) {
        return res.status(500).json({ message: 'Internal Server Error' });
    }
})
