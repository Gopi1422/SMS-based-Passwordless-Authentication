const jwt = require("jsonwebtoken");
const asyncHandler = require("express-async-handler");

const authenticateUser = asyncHandler(async (req, res, next) => {
  const publicUrls = ["/sendOtp", "/verifyOtp", "/refresh"];

  const url = req.url;

  if (publicUrls.includes(url)) {
    next();
  } else {
    if (
      req.headers.authorization &&
      req.headers.authorization.startsWith("Bearer")
    ) {
      try {
        const authHeader = req.headers["authorization"];
        const bearerToken = authHeader.split(" ");
        const accessToken = bearerToken[1];

        if (!accessToken) {
          return res.status(401).send({ data: `Not Authorized, No token!!` });
        }

        jwt.verify(
          accessToken,
          process.env.JWT_AUTH_TOKEN,
          async (err, phone) => {
            if (phone) {
              req.phone = phone.data;
              next();
            } else if (err.name === "TokenExpiredError") {
              return res
                .status(403)
                .send({ success: false, data: `Access Token Expired!!` });
            } else {
              console.error(err);
              res.status(403).send({ err, data: `User not Authenticated!!` });
            }
          }
        );
      } catch (error) {
        console.log(error.response);
      }
    }
  }
});

module.exports = { authenticateUser };

// jmeter - stress measuring tool
