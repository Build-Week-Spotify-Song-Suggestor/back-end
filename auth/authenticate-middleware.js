const jwt = require("jsonwebtoken");
const secrets = require("./secrets.js")
module.exports = (req, res, next) => {

  const [directive, token] = req.headers.authorization.split(" ");

  console.log(directive, token, req.headers.authorization);

  if (!directive || directive != 'bearer') {
    res.status(401).json({ learn: "to type"});
  }

  if(token) {
    jwt.verify(token, secrets.jwtSecret, (err, decodedToken) => {
      if(err) {
        res.status(401).json({you: 'can\'t touch this' });
       } else {
          req.decodedJwt = decodedToken;
          console.log(decodedToken);
          next();
        }
    })
  } else {
    res.status(401).json({ you: 'Will not pass!' });
  }
  
};
