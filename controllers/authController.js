// backend/controllers/authController.js

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { validationResult } = require('express-validator');
const userModel = require('../models/User');
const config = require('../config');

// Controller function for signing up a new user
async function signup(req, res) {
  try {
    // Extract user data from request body
    const { email, password } = req.body;


    // Check if email already exists
    const existingUser = await userModel.getUserByEmail(email);
    if (existingUser) {
      return res.status(400).json({ error: 'Email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const otp = generateOTP();

    // Create a user object
    const newUser = {
      email,
      password: hashedPassword,
      verified: false,
      otp: otp
    };

    // Call the createUser function from the userModel to insert the new user into the database
    const userId = await userModel.createUser(newUser);

    // Send verification email
    await sendVerificationEmail(email, otp);

    // Respond with success message or user data
    res.status(201).json({ message: 'User created successfully. Please check your email for verification.', userId });
  } catch (error) {
    // Handle errors
    console.error('Error signing up user:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
}

async function requestOtp(req, res) {
  const { email } = req.body;

  try {
    const user = userModel.getUserByEmail(email);
    if(!user){
      console.log("user not found");
      return res.status(404).json({ msg: 'User not found' });
    }
    // Generate OTP
    const otp = generateOTP();

    // Save OTP to user document in the database
    await userModel.saveOtp(email, otp);

    // Send OTP to user's email
    await sendVerificationEmail(email, otp);

    res.status(200).json({ msg: 'OTP sent successfully' });
  } catch (error) {
    console.error('Error sending OTP:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};


function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000); // Generate a 6-digit OTP
}

// Function to send verification email
async function sendVerificationEmail(email, otp) {
  // Create a nodemailer transporter
  var transporter = nodemailer.createTransport({
    host: "sandbox.smtp.mailtrap.io",
    port: 2525,
    auth: {
      user: "b3423c951c549e",
      pass: "7c22c65443bbd7"
    }
  });
  // Configure email options
  const mailOptions = {
    from: 'muhammad.akhtar@vaivaltech.com',
    to: email,
    subject: 'Email Verification OTP',
    text: 'Your OTP for email verification is: ${otp}',
    html: '<p>Please click on the following link to verify your account: <a href="http://localhost:3000/verify-otp?email=' + email + '&otp=' + otp + '">Verify</a></p>',
  };

  // Send the email
  await transporter.sendMail(mailOptions);
}

async function verifyOTP(req, res) {
  try {
    // Extract email and OTP from request body
    const { email, otp } = req.body;
    
    // Retrieve the stored OTP from the user model
    const user = await userModel.getUserByEmail(email);
    if (!user) {
      return res.status(404).json({ msg: 'User not found' });
    }
    console.log(user.otp);
    console.log(otp);

    if (user.otp == otp) {
      
      await userModel.updateUserEmailVerified(email);

      const token = generateJWT(email); // Assuming you generate JWT using email

      console.log("token generated")

      // Respond with the generated JWT token
      res.status(200).json({ token });

    } else {
      // If OTP does not match, respond with error message
      res.status(400).json({ error: 'Invalid OTP' });
    }
  } catch (error) {
    // Handle errors
    console.error('Error verifying OTP:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
}


// Sign in user
async function signin(req, res) {
  // Check for validation errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email, password } = req.body;

  try {
    // Check if user exists
    const user = await userModel.getUserByEmail(email);
    if (!user) {
      return res.status(400).json({ msg: 'Invalid credentials' });
    }

    if (!user.verified) {
      return res.status(400).json({ msg: 'User is not verified' });
    }

    // Check if password matches
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ msg: 'Invalid credentials' });
    }
    

    // Generate JWT
    const token = generateJWT(user.email);

    res.json({ token });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
}

// // Request password reset
async function requestPasswordReset(req, res){
  const { email } = req.body;

  try {
    // Find user by email
    const user = await userModel.getUserByEmail(email);

    if (!user) {
      return res.status(404).json({ msg: 'User not found' });
    }

    // Generate password reset token
    const resetToken = generateResetToken(16);
    
    // Save reset token to user document
    const result = await userModel.saveUserResetToken(email, resetToken);
    if(!result){
      return res.status(500).json({ msg: 'Something went wrong' });
    }

    // Send password reset email
    var transporter = nodemailer.createTransport({
      host: "sandbox.smtp.mailtrap.io",
      port: 2525,
      auth: {
        user: "b3423c951c549e",
        pass: "7c22c65443bbd7"
      }
    });

    // Define email options
    const mailOptions = {
      from: 'muhammad.akhtar@vaivaltech.com',
      to: email,
      subject: 'Password Reset Request',
      text: `You have requested to reset your password. Click the following link to reset your password: http://localhost:3000/api/auth/reset?token=${resetToken}`,
      html: `<p>You have requested to reset your password. Click the following link to reset your password: <a href="http://localhost:3000/api/auth/reset?token=${resetToken}">Reset Password</a></p>`
    };

    // Send the email
    const info = await transporter.sendMail(mailOptions);
    console.log('Password reset email sent:', info.messageId);

    res.json({ msg: 'Password reset email sent successfully' });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
}

// Reset password
async function resetPassword(req, res) {
  const { resetToken, newPassword } = req.body;

  try {
    // Find user by reset token
    const user = await userModel.getUserByResetToken(resetToken);
    if (!user) {
      return res.status(400).json({ msg: 'Invalid or expired reset token' });
    }

    // Update password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);
    
    const isUpdated = await userModel.updatePassword(hashedPassword, user.email);

    res.json({ msg: 'Password reset successfully' });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
}

// // Helper function to generate JWT token
function generateJWT(email) {
  const payload = {
    email: { email: email }
  };
  return jwt.sign(payload, config.jwtSecret, { expiresIn: '1h' });
}

// // Helper function to generate OTP and send via email
// function sendOTP(email, otp) {
//   var transport = nodemailer.createTransport({
//     host: "sandbox.smtp.mailtrap.io",
//     port: 2525,
//     auth: {
//       user: "b3423c951c549e",
//       pass: "7c22c65443bbd7"
//     }
//   });


//   const mailOptions = {
//     from: 'muhammad.akhtar@vaivaltech.com',
//     to: email,
//     subject: 'OTP Verification',
//     text: `Your OTP is ${otp}`
//   };

//   transport.sendMail(mailOptions, (error, info) => {
//     if (error) {
//       console.error(error);
//       // Handle error
//     } else {
//       console.log('Email sent: ' + info.response);
//     }
//   });
// }

// Helper function to generate password reset token
function generateResetToken(length) {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let token = '';
  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * characters.length);
    token += characters[randomIndex];
  }
  return token;
}



module.exports = { signup, verifyOTP, signin, requestOtp, requestPasswordReset, resetPassword };