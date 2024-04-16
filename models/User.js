const config = require('../config');
const { MongoClient } = require('mongodb');

// Connection URI
const client = new MongoClient(config.mongoURI);

// Database name
const dbName = 'test_db';

// Collection name
const collectionName = 'users';

// Function to insert a new user
async function createUser(user) {
  try {
    await client.connect();
    console.log('Connected to MongoDB');

    const db = client.db(dbName);
    const collection = db.collection(collectionName);

    const result = await collection.insertOne(user);
    console.log('User inserted:', result.insertedId);

    return result.insertedId;
  } catch (error) {
    console.error('Failed to insert user:', error);
    throw error;
  } finally {
    await client.close();
    console.log('Connection closed');
  }
}

async function updatePassword(password, email) {
  const client = new MongoClient(config.mongoURI);
  const dbName = 'test_db';
  const collectionName = 'users';
  try {
    await client.connect();
    console.log('Connected to MongoDB');

    const db = client.db(dbName);
    const collection = db.collection(collectionName);
    
    const result = await collection.updateOne(
      { email }, 
      { $set: { password: password, resetToken: '' } }
    );
    console.log('Password updated:', result.modifiedCount);

    return result.modifiedCount;
  } catch (error) {
    console.error('Failed to update user password:', error);
    throw error;
  } finally {
    await client.close();
    console.log('Connection closed');
  }
}

async function getUserByEmail(email) {
  const client = new MongoClient(config.mongoURI);
  const dbName = 'test_db';
  const collectionName = 'users';

  try {
    await client.connect();
    const db = client.db(dbName);
    const collection = db.collection(collectionName);

    const user = await collection.findOne({ email });
    return user;
  } catch (error) {
    console.error('Error finding user by email:', error);
    throw error;
  } finally {
    await client.close();
  }
}

async function updateUserEmailVerified(email) {
  const client = new MongoClient(config.mongoURI);
  const dbName = 'test_db';
  const collectionName = 'users';

  try {
    await client.connect();
    const db = client.db(dbName);
    const collection = db.collection(collectionName);

    // Update the user document to mark email as verified
    await collection.updateOne(
      { email }, 
      { $set: { verified: true, otp: '' } }
    );
    console.log('email verified');
    
    // Return true to indicate successful update
    return true;
  } catch (error) {
    console.error('Error updating user email verification status:', error);
    throw error;
  } finally {
    await client.close();
  }
}

async function saveOtp(email, otp) {
    // Connect to MongoDB
    const client = new MongoClient(config.mongoURI);
    const dbName = 'test_db';
    const collectionName = 'users';
  try {
    await client.connect();
    const db = client.db(dbName);
    const collection = db.collection(collectionName);
    // Update the user document with the OTP
    const result = await collection.updateOne({ email }, { $set: { otp: otp } });
    
    if (result.modifiedCount === 0) {
      throw new Error('User not found or OTP not saved.');
    }

    return result;
  } catch (error) {
    console.error('Error saving OTP:', error);
    throw error;
  } finally {
    // Close the MongoDB connection
    await client.close();
  }
}

async function saveUserResetToken(email, resetToken) {
  const client = new MongoClient(config.mongoURI);
  const dbName = 'test_db';
  const collectionName = 'users';

  try {
    await client.connect();
    const db = client.db(dbName);
    const collection = db.collection(collectionName);

    // Update the user document to mark email as verified
    await collection.updateOne(
      { email }, 
      { $set: { resetToken: resetToken } }
    );
    
    // Return true to indicate successful update
    return true;
  } catch (error) {
    console.error('Error updating user email verification status:', error);
    throw error;
  } finally {
    await client.close();
  }
}

async function getUserByResetToken(resetToken) {
  const client = new MongoClient(config.mongoURI);
  const dbName = 'test_db';
  const collectionName = 'users';

  try {
    await client.connect();
    const db = client.db(dbName);
    const collection = db.collection(collectionName);

    const user = await collection.findOne({ resetToken });
    return user;
  } catch (error) {
    console.error('Error finding user by email:', error);
    throw error;
  } finally {
    await client.close();
  }
}

async function resetPassword(token, newPassword)
{
  try {
    await client.connect();
    console.log('Connected to MongoDB');

    const db = client.db(dbName);
    const collection = db.collection(collectionName);

    // Find user by reset token
    const user = await collection.findOne({ resetToken });

    if (!user) {
      return res.status(400).json({ msg: 'Invalid or expired reset token' });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update user's password and reset token
    await collection.updateOne({ resetToken }, { $set: { password: hashedPassword, resetToken: null } });

    res.json({ msg: 'Password reset successfully' });
  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({ msg: 'Internal server error' });
  } finally {
    await client.close();
    console.log('Connection closed');
  }
}

module.exports = { createUser,getUserByEmail, updateUserEmailVerified, saveOtp, saveUserResetToken, resetPassword, getUserByResetToken, updatePassword };
