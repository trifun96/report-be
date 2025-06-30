const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URL);
    console.log('✅ Povezan sa MongoDB bazom');
  } catch (err) {
    console.error('❌ Greška pri povezivanju na MongoDB:', err.message);
    process.exit(1);
  }
};

module.exports = connectDB;