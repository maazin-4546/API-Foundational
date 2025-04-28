const jwt = require('jsonwebtoken');
const { Users } = require('../models/Users');

const authMiddleware = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).send({ message: 'Authorization token missing or invalid.' });
        }

        const token = authHeader.split(' ')[1];

        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        const user = await Users.findById(decoded.userId);

        if (!user) {
            return res.status(401).send({ message: 'User not found.' });
        }

        req.user = {
            _id: user._id,
            email: user.email,
            name: user.name,            
        };

        next();

    } catch (error) {
        console.error('Auth Middleware Error:', error);
        return res.status(401).send({ message: 'Invalid or expired token.' });
    }
};

module.exports = authMiddleware;
