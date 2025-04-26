const { default: mongoose } = require("mongoose");

const UserSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  isAdmin: { type: Boolean, default: false },
  isEmailVerified: { type: Boolean, default: false },
  isBlocked: { type: Boolean, default: false },
  isDeleted: { type: Boolean, default: false },
  emailVerificationOtp: { type: String },
  emailVerificationOtpExpiry: { type: Date },
  passwordResetOtp: { type: String },
  passwordResetOtpExpiry: { type: Date },
  lastLoginAt: { type: Date },
  otpRequestHistory: {
    type: [Date],
    default: [],
  },

}, { timestamps: true });


const Users = mongoose.model("Users", UserSchema);
module.exports = { Users };
