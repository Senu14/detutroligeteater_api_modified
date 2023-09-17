import jwt from 'jsonwebtoken';

// Middleware function to verify and potentially refresh tokens
function verifyToken(req, res, next) {
  // Get the access token from the request header or wherever it's stored
  const access_token = req.headers.authorization?.split(' ')[1];

  if (!access_token) {
    return res.status(401).json({ error: 'Token not provided' });
  }

  // Verify the access token
  jwt.verify(access_token, process.env.TOKEN_ACCESS_KEY, (err, decoded) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        // Access token has expired
        // Handle token expiration here by generating a new access token
        // and sending it back to the client
        const newAccessToken = jwt.sign({ data: decoded.data }, process.env.TOKEN_ACCESS_KEY, {
          expiresIn: '1h', // Set a new expiration time
        });

        // Attach the new access token to the response header for the client to use
        res.setHeader('Authorization', `Bearer ${newAccessToken}`);
        return res.status(401).json({ error: 'Access token expired', newAccessToken });
      } else {
        // Handle other JWT verification errors
        console.error('JWT Verification Error:', err);
        return res.status(403).json({ error: 'Invalid token' });
      }
    } else {
      // Token is valid
      // Proceed with the request
      next();
    }
  });
}

export { verifyToken };
