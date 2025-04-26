const express = require('express')
const router = express.Router()

const { userSignup, verifyOtpAndSignup, userLogin, userLogout, forgotPassword, resetPassword, resendOtp } = require('../controller/userController')

router.post("/signup", userSignup)

router.post("/verifyOtp-signup", verifyOtpAndSignup)

router.post("/login", userLogin)

router.post("/logout", userLogout)

router.post("/forgot-password", forgotPassword)

router.post("/reset-password", resetPassword)

router.post("/resend-otp", resendOtp)


module.exports = router