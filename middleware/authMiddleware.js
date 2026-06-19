const jwt = require("jsonwebtoken");

const protect = (req, res, next) => {
  try {
    let token;

    if (
      req.headers.authorization &&
      req.headers.authorization.startsWith("Bearer")
    ) {
      token = req.headers.authorization.split(" ")[1];
    }

    if (!token) {
      return res.status(401).json({
        message: "Not authorized, no token",
      });
    }

    const decoded = jwt.verify(token, "secretkey123");

    req.user = decoded;

    next();
  } catch (error) {
    return res.status(401).json({
      message: "Token invalid or expired",
    });
  }
};

module.exports = protect;