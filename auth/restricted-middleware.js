const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const Users = require('../users/users-model.js');

module.exports = (req, res, next) => {
const token = req.headers.authorization;

  if (token) {
    const secret = process.env.JWT_SECRET || 'is it secret, is it safe?';
    //check token validity 
    jwt.verify(token, secret, (err, decodedToken) => {
      if (err) {
        // token modified
        res.status(401).json({ error: 'Invalid token'})
      } else {
        req.decodedJwt = decodedToken;
        next();
      }
    }) //needs secret to check validity 
  } else {
    res.status(400).json({ message: 'No credentials provided' });
  }
};
