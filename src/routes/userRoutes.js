const express = require("express");
const {
  sendOtp,
  verifyOtp,
  refresh,
  test,
} = require("../controllers/userController");

const router = express.Router();

router.post("/sendOtp", sendOtp);
router.post("/verifyOtp", verifyOtp);
router.post("/refresh", refresh);
router.get("/test", test);

module.exports = router;
