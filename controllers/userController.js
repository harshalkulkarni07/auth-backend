const asyncHandler = require("express-async-handler");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
const User = require("../models/userModel");


//@desc Register a user
//@route POST /api/users/register
//@access public
const registerUser = asyncHandler(async (req, res) => {
  const { username, email, password } = req.body;
  if ( !email || !password) {
    res.status(400);
    throw new Error("All fields are mandatory!");
  }
  const userAvailable = await User.findOne({ email });
  if (userAvailable) {
    res.status(400);
    throw new Error("User already registered!");
  }

  //Hash password
  const hashedPassword = await bcrypt.hash(password, 10);
  console.log("Hashed Password: ", hashedPassword);
  const user = await User.create({
    username,
    email,
    password: hashedPassword,
  });

  console.log(`User created ${user}`);
  if (user) {
    res.status(201).json({ _id: user.id, email: user.email });
  } else {
    res.status(400);
    throw new Error("User data is not valid");
  }
  res.json({ message: "Register the user" });
});

//@desc Login user
//@route POST /api/users/login
//@access public
const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    res.status(400);
    throw new Error("All fields are mandatory!");
  }
  const user = await User.findOne({ email });
  console.log(process.env.ACCESS_TOKEN_SECERT)
  //compare password with hashedpassword
  if (user && (await bcrypt.compare(password, user.password))) {
    const accessToken = jwt.sign(
      {
        user: {
          username: user.username,
          email: user.email,
          id: user.id,
        },
      },
      process.env.ACCESS_TOKEN_SECERT,
      { expiresIn: "15m" }
    );
    res.status(200).json({ accessToken });
  } else {
    res.status(401);
    throw new Error("email or password is not valid");
  }
});

//@desc Current user info
//@route POST /api/users/current
//@access private
const currentUser = asyncHandler(async (req, res) => {
  res.json(req.user);
});


//@desc Forgot Password
//@route POST /api/users/forgotpassword
//@access public
const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });

  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }

  // Generate a token for password reset
  const resetToken = jwt.sign({ id: user._id }, process.env.RESET_TOKEN_SECRET, {
    expiresIn: "30m",
  });



  // Google not supporting this for my email need to update 
  // const resetLink = `${req.protocol}://${req.get(
  //   "host"
  // )}/api/users/resetpassword/${resetToken}`;

  // // Configure nodemailer to send the email
  // const transporter = nodemailer.createTransport({
  //   // Configure your email service
  //   // For example, using Gmail:
  //   service: "gmail",
  //   auth: {
  //     user: "hsk13198@gmail.com",
  //     pass: "Harsh@1234",
  //   },
  // });

  // const mailOptions = {
  //   from: "hsk13198@gmail.com",
  //   to: user.email,
  //   subject: "Password Reset",
  //   text: `Click on the following link to reset your password: ${resetLink}`,
  // };

  // try {
  //   await transporter.sendMail(mailOptions);
  //   console.log("Password reset email sent successfully.");
  // } catch (error) {
  //   console.error("Error sending password reset email:", error);
  //   throw new Error("Failed to send password reset email");
  // }
  res.status(200).json({
    message: "Password reset token generated",
    resetToken,
  });
});

//@desc Reset Password
//@route PUT /api/users/resetpassword/:resettoken
//@access public

const resetPassword = asyncHandler(async (req, res) => {
  const { resetToken, newPassword } = req.body;

  // Verify the reset token
  jwt.verify(resetToken, process.env.RESET_TOKEN_SECRET, async (err, decoded) => {
    if (err) {
      res.status(401);
      throw new Error('Invalid or expired token');
    }

    const userId = decoded.id;

    try {
      // Generate a hash of the new password
      const hashedPassword = await bcrypt.hash(newPassword, 10);

      // Update the user's password in the database
      const user = await User.findByIdAndUpdate(userId, { password: hashedPassword });

      if (!user) {
        // Handle the case where the user with the given ID is not found
        res.status(404).json({ message: 'User not found' });
      } else {
        res.status(200).json({ message: 'Password reset successfully' });
      }
    } catch (error) {
      console.error('Error resetting password:', error);
      res.status(500).json({ message: 'Failed to reset password' });
    }
  });
});

module.exports = { registerUser, loginUser, currentUser, resetPassword, forgotPassword};
