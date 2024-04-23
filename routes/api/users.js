const express = require('express');
require('dotenv').config();
const router = express.Router();
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator');
const normalize = require('normalize-url');
const nodemailer = require('nodemailer'); // for sending verification emails

const User = require('../../models/User');

// Email configuration for nodemailer
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  auth: {
    user: process.env.EMAIL_ADDRESS,
    pass: process.env.EMAIL_PASSWORD 
  },
  tls: {
    rejectUnauthorized: false,
  },
});

// @route    POST api/users
// @desc     Register user and send verification email
// @access   Public
router.post(
  '/',
  check('name', 'Name is required').notEmpty(),
  check('email', 'Please include a valid email').isEmail(),
  check(
    'password',
    'Please enter a password with 6 or more characters'
  ).isLength({ min: 6 }),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password } = req.body;

    try {
      let user = await User.findOne({ email });

      if (user) {
        return res
          .status(400)
          .json({ errors: [{ msg: 'User already exists' }] });
      }

      const avatar = normalize(
        gravatar.url(email, {
          s: '200',
          r: 'pg',
          d: 'mm'
        }),
        { forceHttps: true }
      );

      user = new User({
        name,
        email,
        avatar,
        password,
        isVerified: false // Adding the isVerified field to the user document
      });

      const salt = await bcrypt.genSalt(10);

      user.password = await bcrypt.hash(password, salt);

      // Generate a verification token
      const verificationToken = jwt.sign(
        { userId: user._id },
        process.env.EMAIL_VERIFICATION_SECRET,
        { expiresIn: '1 day' }
      );

      // Sending the verification email
      await transporter.sendMail({
        from: 'your_email@example.com',
        to: email,
        subject: 'Account Verification',
        html: `<p>Please click <a href="${process.env.BASE_URL}/api/users/verify-email/${verificationToken}">here</a> to verify your email address.</p>`
      });

      await user.save();

      res.json({
        msg: 'Registration successful. Please check your email for verification.'
      });
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server error');
    }
  }
);

// @route    GET api/users/verify-email/:token
// @desc     Verify user's email address
// @access   Public
router.get('/verify-email/:token', async (req, res) => {
  const token = req.params.token;

  try {
    const decoded = jwt.verify(token, process.env.EMAIL_VERIFICATION_SECRET);

    // Mark user as verified
    await User.findByIdAndUpdate(decoded.userId, { isVerified: true });

    res.json({ msg: 'Email verified successfully. You can now login.' });
  } catch (err) {
    console.error(err.message);
    res.status(400).json({ msg: 'Invalid or expired token.' });
  }
});

module.exports = router;
