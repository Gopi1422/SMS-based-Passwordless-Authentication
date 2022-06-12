const asyncHandler = require("express-async-handler");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const User = require("../models/userModel");

let refreshTokens = [];

const sendOtp = asyncHandler(async (req, res) => {
  const accountSid = process.env.ACCOUNT_SID;
  const authToken = process.env.AUTH_TOKEN;
  const client = require("twilio")(accountSid, authToken);
  const smsKey = process.env.SMS_SECRET_KEY;
  const { name, phone, email, pic, isLogin } = req.body;

  if (isLogin) {
    // login
    if (!phone) {
      res.status(400);
      throw new Error("Please Enter the phone number!!");
    }
  } else {
    // sign up
    if (!name || !email || !phone) {
      res.status(400);
      throw new Error("Please Enter all the fields!!");
    }
  }

  const userExists = await User.findOne({ phone });
  // console.log(userExists);

  if (userExists && !isLogin) {
    return res
      .status(400)
      .send({ msg: "User Already Exists!!", success: false });
  } else if (!userExists && isLogin) {
    return res
      .status(404)
      .send({ msg: "User doesn't exists!!", success: false });
  }

  const otp = Math.floor(100000 + Math.random() * 900000);
  const ttl = 2 * 60 * 1000;
  const expires = Date.now() + ttl;
  const data = `${phone}.${otp}.${expires}`;
  const hash = crypto.createHmac("sha256", smsKey).update(data).digest("hex");
  const fullHash = `${hash}.${expires}`;

  // client.messages
  //   .create({
  //     body: `Your One Time Login Password for CFM is ${otp}`,
  //     from: +19403505833,
  //     to: phone,
  //   })
  //   .then((messages) => console.log(messages))
  //   .catch((err) => console.error(err));

  res.status(200).send({ name, phone, email, hash: fullHash, otp, isLogin });
});

const verifyOtp = asyncHandler(async (req, res) => {
  const JWT_AUTH_TOKEN = process.env.JWT_AUTH_TOKEN;
  const JWT_REFRESH_TOKEN = process.env.JWT_REFRESH_TOKEN;
  const smsKey = process.env.SMS_SECRET_KEY;
  const { name, phone, email, hash, otp, isLogin } = req.body;

  let [hashValue, expires] = hash.split(".");
  let now = Date.now();

  if (now > parseInt(expires)) {
    return res.status(504).send({ msg: `Timeout!! Pls Try again..` });
  }

  const data = `${phone}.${otp}.${expires}`;
  const newCalculateHash = crypto
    .createHmac("sha256", smsKey)
    .update(data)
    .digest("hex");

  if (newCalculateHash === hashValue) {
    const accessToken = jwt.sign({ data: phone }, JWT_AUTH_TOKEN, {
      expiresIn: "1d",
    });
    const refreshToken = jwt.sign({ data: phone }, JWT_REFRESH_TOKEN, {
      expiresIn: "1y",
    });
    refreshTokens.push(refreshToken);

    let user = "";
    if (!isLogin) {
      user = await User.create({ name, phone, email });
    } else {
      user = await User.findOne({ phone });
    }

    if (user) {
      res.status(202).send({
        _id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        msg: `Device Verified!!`,
        accessToken: accessToken,
        refreshToken: refreshToken,
        authSession: true,
        refreshTokenID: true,
        accessExpiry: new Date().getTime() + 86400000,
        refreshExpiry: new Date().getTime() + 3557600000,
      });
    } else {
      res
        .status(400)
        .send({ verification: false, msg: "Failed to Create the User!!" });
    }
  } else {
    return res
      .status(400)
      .send({ verification: false, msg: "Incorrect OTP!!" });
  }
});

const refresh = (req, res) => {
  const JWT_AUTH_TOKEN = process.env.JWT_AUTH_TOKEN;
  const JWT_REFRESH_TOKEN = process.env.JWT_REFRESH_TOKEN;

  const authHeader = req.headers["authorization"];
  const bearerToken = authHeader.split(" ");
  const refreshToken = bearerToken[1];

  if (refreshToken === "undefined") {
    return res
      .status(403)
      .send({ msg: `Refresh Token not found, Please Login again..` });
  }

  if (!refreshTokens.includes(refreshToken))
    return res.status(403).send({
      msg: `Refresh Token blocked, Please Login again..`,
      refreshToken: refreshToken,
    });

  jwt.verify(refreshToken, JWT_REFRESH_TOKEN, async (err, phone) => {
    if (!err) {
      const accessToken = jwt.sign({ data: phone }, JWT_AUTH_TOKEN, {
        expiresIn: "1d",
      });

      res.status(202).send({
        previousSessionExpiry: true,
        success: true,
        accessToken: accessToken,
        authSession: true,
        refreshToken: refreshToken,
        refreshTokenID: true,
        accessExpiry: new Date().getTime() + 86400000,
      });
    } else {
      return res
        .status(403)
        .send({ success: false, msg: `Invalid Refresh Token!!` });
    }
  });
};

const test = (req, res) => {
  res.send("Testing API!");
};

module.exports = { sendOtp, verifyOtp, refresh, test };
