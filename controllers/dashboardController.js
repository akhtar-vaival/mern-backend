// backend/controllers/dashboardController.js

const userModel = require('../models/User');

// Get dashboard data
exports.getDashboard = async (req, res) => {
  try {
    // Fetch user data based on the authenticated user
    const email = req.user.email;
    const user = await userModel.getUserByEmail(email);
    console.log(user);
    if (!user) {
      return res.status(404).json({ msg: 'User not found' });
    }

    res.json(user);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
};
