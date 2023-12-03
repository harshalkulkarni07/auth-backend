const express = require("express");
const {
  registerUser,
  currentUser,
  loginUser,
  forgotPassword,
  resetPassword
} = require("../controllers/userController");
const validateToken = require("../middleware/validateTokenHandler");

const router = express.Router();

router.post("/register", registerUser);

router.post("/login", loginUser);

router.get("/current", validateToken, currentUser);

router.post("/forgotpassword", forgotPassword);

router.post("/resetpassword", resetPassword);
module.exports = router;
