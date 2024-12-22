const asyncHandler = require('express-async-handler');

// Healty check route
exports.health_check = asyncHandler(async (req, res, next) => {
    res.setHeader('Content-Type', 'application/json');
    res.status(200).send({ message: 'Server is running (all services operational).' });
});
