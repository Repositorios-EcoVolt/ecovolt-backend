const jwt = require('jsonwebtoken');

exports.checkToken = (req, res, next) => {
    const header = req.headers['authorization'];

    if (typeof header !== 'undefined') {
        const bearer = header.split(' ');
        const token = bearer[1];

        req.token = token;

        jwt.verify(req.token, process.env.JWT_SECRET, (err, authorizedData) => {
            if (err) {
                res.status(403).json({ 
                    message: 'Autentication failed.', 
                    error: err.message 
                });
            } else {
                next();
            }
        });
    } else {
        res.status(403).json({ message: 'Authentication credentials were not provided' });
    }
}
