const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  lozinka: String,
  delatnost: String,
  adresa: String,
  isActive: { type: Boolean, default: false },
  activationToken: String,
  activationTokenExpires: Date,
  resetToken: { type: String },
  resetTokenExpires: { type: Date },
  role: {
    type: String,
    enum: ["user", "admin"],
    default: "user",
  },
});

module.exports = mongoose.model("User", userSchema);
