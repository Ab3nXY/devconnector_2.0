const mongoose = require('mongoose');
require('dotenv').config();
const githubToken = process.env.GITHUB_TOKEN;
const jwtSecret = process.env.JWT_SECRET;


const connectDB = async () => {
  try {
    const db = process.env.MONGO_URI;
    await mongoose.connect(db, {
      useNewUrlParser: true,
      useCreateIndex: true,
      useFindAndModify: false,
      useUnifiedTopology: true
    });

    console.log('MongoDB Connected...');
  } catch (err) {
    console.error(err.message);
    // Exit process with failure
    process.exit(1);
  }
};

module.exports = connectDB;
