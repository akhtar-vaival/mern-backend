// backend/middlewares/authMiddleware.js

const jwt = require('jsonwebtoken');
const config = require('../config');

exports.authMiddleware = (req, res, next) => {
  // Get token from header
  const token = req.header('x-auth-token');
  console.log(token)
  // Check if no token
  if (!token) {
    return res.status(401).json({ msg: 'No token, authorization denied' });
  }

  // Verify token
  try {
    console.log(token);
    const decoded = jwt.verify(token, config.jwtSecret);
    req.user = decoded.email;
    console.log(req.user);
    next();
  } catch (err) {
    res.status(401).json({ msg: 'Token is not valid' });
  }
};
