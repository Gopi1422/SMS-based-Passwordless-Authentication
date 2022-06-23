const asyncHandler = require("express-async-handler");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const User = require("../models/userModel");
const {
  validator,
  authSchema,
  registerUserSchema,
} = require("../helpers/validate_schema");
// const nodemailer = require("nodemailer");

let refreshTokens = [];

const sendOtp = asyncHandler(async (req, res) => {
  const accountSid = process.env.ACCOUNT_SID;
  const authToken = process.env.AUTH_TOKEN;
  const client = require("twilio")(accountSid, authToken);
  const smsKey = process.env.SMS_SECRET_KEY;
  const nodemailer = require("nodemailer");
  const { name, phone, email, pic, isLogin } = req.body;

  if (!isLogin) validator(registerUserSchema, req, res);
  else validator(authSchema, req, res);

  if (isLogin) {
    // login
    if (!email) {
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

  // console.log(email);
  const userExists = await User.findOne({ email });
  // console.log(userExists);

  if (userExists && !isLogin) {
    return res
      .status(400)
      .send({ data: "User Already Exists!!", success: false });
  } else if (!userExists && isLogin) {
    return res
      .status(404)
      .send({ data: "User doesn't exists!!", success: false });
  }

  const otp = Math.floor(100000 + Math.random() * 900000);
  const ttl = 2 * 60 * 1000;
  const expires = Date.now() + ttl;
  const data = `${email}.${otp}.${expires}`;
  const hash = crypto.createHmac("sha256", smsKey).update(data).digest("hex");
  const fullHash = `${hash}.${expires}`;
  let error;

  const message = `<div style='min-width:1000px;overflow:auto;line-height:2'><div style='margin:10px auto;width:80%;'><div style='border-bottom:1px solid #eee'><a href='' style='font-size:1.4em;color: #00466a;text-decoration:none;font-weight:600'>Cheat-Chat</a></div><p>Hi,</p><p>Your OTP for Cheat-Chat is shown below. Use the following OTP to complete your Sign Up/Login procedures. OTP is valid for 2 minutes</p><h2 style='background: #00466a;margin: 0 auto;width: max-content;padding: 0 10px;color: #fff;border-radius: 4px;'>${otp}</h2><p>Regards,<br />Cheat-Chat</p></div></div></div>`;

  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: "cheatchat05@gmail.com",
      pass: "pyojyzoybeqolspr",
    },
  });

  const mailOptions = {
    name: "Cheat-Chat",
    from: "Cheat-Chat <cheatchat05@gmail.com>",
    to: email,
    subject: "Verify Your Email",
    html: message,
  };

  await transporter.sendMail(mailOptions, function (err, info) {
    if (err) {
      error = err;
      // console.log(error);
    } else {
      console.log("Email sent successfully!!");
    }
  });

  // await client.messages
  //   .create({
  //     body: `Your One Time Login Password for CFM is ${otp}`,
  //     from: +19403505833,
  //     to: phone,
  //   })
  //   .then((messages) => console.log(messages))
  //   .catch((err) => {
  //     error = err;
  //     // console.log(error);
  //   });

  if (error) {
    // console.log("Error...");
    return res.status(400).send({
      success: false,
      data: "Failed to send OTP!!",
    });
  }

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
    return res.status(504).send({ data: `Timeout!! Pls Try again..` });
  }

  const data = `${email}.${otp}.${expires}`;
  const newCalculateHash = crypto
    .createHmac("sha256", smsKey)
    .update(data)
    .digest("hex");

  if (newCalculateHash === hashValue || isLogin === "guest") {
    // console.log(isLogin + " & " + newCalculateHash);
    const accessToken = jwt.sign({ data: email }, JWT_AUTH_TOKEN, {
      expiresIn: "3d",
    });
    const refreshToken = jwt.sign({ data: email }, JWT_REFRESH_TOKEN, {
      expiresIn: "1y",
    });
    refreshTokens.push(refreshToken);

    let user = "";
    if (isLogin === "false") {
      // console.log("Creating User..");
      user = await User.create({ name, phone, email });
    } else {
      user = await User.findOne({ email });
    }

    if (user) {
      res.status(202).send({
        _id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        pic: user.pic,
        data: `Device Verified!!`,
        accessToken: accessToken,
        refreshToken: refreshToken,
        authSession: true,
        refreshTokenID: true,
        accessExpiry: new Date().getTime() + 86400000 * 3, // 86400000
        refreshExpiry: new Date().getTime() + 3557600000,
      });
    } else {
      res
        .status(400)
        .send({ verification: false, data: "Failed to Create the User!!" });
    }
  } else {
    return res
      .status(400)
      .send({ verification: false, data: "Incorrect OTP!!" });
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
      .send({ data: `Refresh Token not found, Please Login again..` });
  }

  if (!refreshTokens.includes(refreshToken))
    return res.status(403).send({
      data: `Refresh Token blocked, Please Login again..`,
      refreshToken: refreshToken,
    });

  jwt.verify(refreshToken, JWT_REFRESH_TOKEN, async (err, phone) => {
    if (!err) {
      // console.log(phone);
      const accessToken = jwt.sign({ data: phone.data }, JWT_AUTH_TOKEN, {
        expiresIn: "30s",
      });

      res.status(202).send({
        previousSessionExpiry: true,
        success: true,
        accessToken: accessToken,
        authSession: true,
        refreshToken: refreshToken,
        refreshTokenID: true,
        accessExpiry: new Date().getTime() + 29999, // 86400000
      });
    } else {
      return res
        .status(403)
        .send({ success: false, data: `Invalid Refresh Token!!` });
    }
  });
};

const test = (req, res) => {
  res.send("Testing API!");
};

module.exports = { sendOtp, verifyOtp, refresh, test };

// const sendOtp = asyncHandler(async (req, res) => {
//   const accountSid = process.env.ACCOUNT_SID;
//   const authToken = process.env.AUTH_TOKEN;
//   const client = require("twilio")(accountSid, authToken);
//   const smsKey = process.env.SMS_SECRET_KEY;
//   const { name, phone, email, pic, isLogin } = req.body;

//   if (!isLogin) validator(registerUserSchema, req, res);
//   else validator(authSchema, req, res);

//   if (isLogin) {
//     // login
//     if (!phone) {
//       res.status(400);
//       throw new Error("Please Enter the phone number!!");
//     }
//   } else {
//     // sign up
//     if (!name || !email || !phone) {
//       res.status(400);
//       throw new Error("Please Enter all the fields!!");
//     }
//   }

//   const userExists = await User.findOne({ phone });
//   // console.log(userExists);

//   if (userExists && !isLogin) {
//     return res
//       .status(400)
//       .send({ data: "User Already Exists!!", success: false });
//   } else if (!userExists && isLogin) {
//     return res
//       .status(404)
//       .send({ data: "User doesn't exists!!", success: false });
//   }

//   const otp = Math.floor(100000 + Math.random() * 900000);
//   const ttl = 2 * 60 * 1000;
//   const expires = Date.now() + ttl;
//   const data = `${phone}.${otp}.${expires}`;
//   const hash = crypto.createHmac("sha256", smsKey).update(data).digest("hex");
//   const fullHash = `${hash}.${expires}`;

//   // client.messages
//   //   .create({
//   //     body: `Your One Time Login Password for CFM is ${otp}`,
//   //     from: +19403505833,
//   //     to: phone,
//   //   })
//   //   .then((messages) => console.log(messages))
//   //   .catch((err) => console.error(err));

//   res.status(200).send({ name, phone, email, hash: fullHash, otp, isLogin });
// });

// const verifyOtp = asyncHandler(async (req, res) => {
//   const JWT_AUTH_TOKEN = process.env.JWT_AUTH_TOKEN;
//   const JWT_REFRESH_TOKEN = process.env.JWT_REFRESH_TOKEN;
//   const smsKey = process.env.SMS_SECRET_KEY;
//   const { name, phone, email, hash, otp, isLogin } = req.body;

//   let [hashValue, expires] = hash.split(".");
//   let now = Date.now();

//   if (now > parseInt(expires)) {
//     return res.status(504).send({ data: `Timeout!! Pls Try again..` });
//   }

//   const data = `${phone}.${otp}.${expires}`;
//   const newCalculateHash = crypto
//     .createHmac("sha256", smsKey)
//     .update(data)
//     .digest("hex");

//   if (newCalculateHash === hashValue) {
//     const accessToken = jwt.sign({ data: phone }, JWT_AUTH_TOKEN, {
//       expiresIn: "120s",
//     });
//     const refreshToken = jwt.sign({ data: phone }, JWT_REFRESH_TOKEN, {
//       expiresIn: "1y",
//     });
//     refreshTokens.push(refreshToken);

//     let user = "";
//     if (isLogin === "false") {
//       // console.log("Creating User..");
//       user = await User.create({ name, phone, email });
//     } else {
//       user = await User.findOne({ phone });
//     }

//     if (user) {
//       res.status(202).send({
//         _id: user._id,
//         name: user.name,
//         email: user.email,
//         phone: user.phone,
//         pic: user.pic,
//         data: `Device Verified!!`,
//         accessToken: accessToken,
//         refreshToken: refreshToken,
//         authSession: true,
//         refreshTokenID: true,
//         accessExpiry: new Date().getTime() + 29999, // 86400000
//         refreshExpiry: new Date().getTime() + 3557600000,
//       });
//     } else {
//       res
//         .status(400)
//         .send({ verification: false, data: "Failed to Create the User!!" });
//     }
//   } else {
//     return res
//       .status(400)
//       .send({ verification: false, data: "Incorrect OTP!!" });
//   }
// });
