const express = require('express');
const router = express.Router();
const { check } = require('express-validator');
const { signup, signin, requestPasswordReset, resetPassword, verifyOTP, requestOtp } = require('../controllers/authController');
const { validateSignup } = require('../middlewares/validationMiddleware');
const { authMiddleware } = require('../middlewares/authMiddleware');
const { errorHandler } = require('../middlewares/errorMiddleware');

// Signup route
router.post(
  '/signup',
  [
    // Validate user input
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Please enter a password with 6 or more characters').isLength({ min: 6 }),
    // Handle errors
    validateSignup
  ],
  signup
);


// Request OTP route
router.post(
  '/request-otp',
  [
    check('email', 'Please enter a valid email').isEmail(),
  ],
  requestOtp
);

// Verify OTP route
router.post(
  '/verify-otp',
  [
    check('email', 'Please enter a valid email').isEmail(),
    check('otp', 'Please enter a valid OTP').isNumeric().isLength({ min: 6, max: 6 }),
  ],
  verifyOTP
);


// Signin route
router.post(
  '/signin',
  [
    // Validate user input
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Password is required').exists(),
    // Handle errors
    errorHandler
  ],
  signin
);

// Request password reset route
router.post(
    '/request-password-reset',
    [
      check('email', 'Please include a valid email').isEmail(),
      errorHandler
    ],
    requestPasswordReset
  );

// Reset password route
router.post(
    '/reset-password',
    [
      // Validate reset token and new password
      check('resetToken', 'Reset token is required').exists(),
      check('newPassword', 'Please enter a password with 6 or more characters').isLength({ min: 6 }),
      // Handle errors
      errorHandler
    ],
    resetPassword
  );

// Error handling middleware
router.use(errorHandler);

module.exports = router;
