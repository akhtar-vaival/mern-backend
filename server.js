// backend/server.js

const express = require('express');
const { MongoClient } = require('mongodb');
const authRoutes = require('./routes/authRoutes');
const dashboardRoutes = require('./routes/dashboardRoutes');
const config = require('./config');

const app = express();

// Middleware to parse JSON bodies
app.use(express.json());

// Connect to MongoDB
const client = new MongoClient(config.mongoURI, { useNewUrlParser: true, useUnifiedTopology: true });
async function connectToDB() {
  try {
      await client.connect();
      console.log("Connected to MongoDB cluster");
  } catch (error) {
      console.error("Error connecting to MongoDB cluster:", error);
  }
}

// Define routes
app.use('/api/auth', authRoutes);
app.use('/api/dashboard', dashboardRoutes);

const PORT = 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

connectToDB();