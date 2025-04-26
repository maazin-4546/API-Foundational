const { Users } = require("../models/Users")
const { findByEmail } = require("../services/userServices")
const bcrypt = require("bcryptjs")
const nodemailer = require("nodemailer")
const jwt = require("jsonwebtoken")


const verifyOtpAndSignup = async (req, res) => {
    const { email, otp } = req.body;

    if (!email || !otp) {
        return res.status(400).send({ message: "Email and OTP are required" });
    }

    const user = await findByEmail({ email });

    if (!user) {
        return res.status(404).send({ message: "User not found. Please sign up first." });
    }

    if (user.isEmailVerified) {
        return res.status(400).send({ message: "User already verified." });
    }

    if (user.emailVerificationOtp !== otp) {
        return res.status(400).send({ message: "Invalid OTP" });
    }

    if (new Date() > user.emailVerificationOtpExpiry) {
        return res.status(400).send({ message: "OTP expired" });
    }

    user.isEmailVerified = true;
    user.emailVerificationOtp = undefined;
    user.emailVerificationOtpExpiry = undefined;

    await user.save();

    res.status(200).send({
        success: true,
        message: "Email verified and user created successfully",
        user
    });
};

const userSignup = async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).send({ message: "Name, email, and password are required" });
    }

    const existingUser = await findByEmail({ email });

    // --- RATE LIMITING LOGIC START ---
    if (existingUser) {
        const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000); // 1 hour ago

        if (!existingUser.otpRequestHistory) {
            existingUser.otpRequestHistory = [];
        }

        // Filter out only the requests in the last 1 hour
        const recentOtpRequests = existingUser.otpRequestHistory.filter(
            (timestamp) => timestamp > oneHourAgo
        );

        if (recentOtpRequests.length >= 5) {
            return res.status(429).send({ message: "Too many OTP requests. Please try again after some time." });
        }

        existingUser.otpRequestHistory.push(new Date());
        await existingUser.save();
    }

    if (existingUser && existingUser.isEmailVerified) {
        return res.status(208).send({ message: "User already exists and is verified" });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const emailVerificationOtpExpiry = new Date(Date.now() + 5 * 60 * 1000); // 5 min expiry

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create or update unverified user
    let user;
    if (existingUser) {
        user = await Users.findByIdAndUpdate(existingUser._id, {
            name,
            password: hashedPassword,
            emailVerificationOtp: otp,
            emailVerificationOtpExpiry,
            otpRequestHistory: existingUser.otpRequestHistory, // update history
        }, { new: true });
    } else {
        user = new Users({
            name,
            email,
            password: hashedPassword,
            emailVerificationOtp: otp,
            emailVerificationOtpExpiry,
            otpRequestHistory: [new Date()], // initialize history
        });
        await user.save();
    }

    // Send OTP via email
    const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
            user: process.env.NODEMAILER_EMAIL,
            pass: process.env.NODEMAILER_PASSWORD
        }
    });

    const mailOptions = {
        from: `"ZakDoc" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: "OTP Verification - ZakDoc",
        text: `Your OTP for email verification is: ${otp}. It expires in 5 minutes.`
    };

    try {
        await transporter.sendMail(mailOptions);
        res.status(200).send({ message: "OTP sent to email successfully" });
    } catch (error) {
        res.status(500).send({ message: "Failed to send OTP", error: error.message });
    }
};

const userLogin = async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).send({ message: "Both email and password are required" });
        }

        const checkUser = await findByEmail({ email });
        if (!checkUser) {
            return res.status(401).send({ message: "Invalid credentials" });
        }

        if (checkUser.isDeleted) {
            return res.status(403).send({ message: "Account is no longer accessible" });
        }

        if (checkUser.isBlocked) {
            return res.status(403).send({ message: "User is temporarily blocked" });
        }

        const isPasswordValid = await bcrypt.compare(password, checkUser.password);
        if (!isPasswordValid) {
            return res.status(401).send({ message: "Invalid credentials" });
        }

        if (!checkUser.isEmailVerified) {
            return res.status(401).send({ message: "Email is not verified" });
        }

        checkUser.lastLoginAt = new Date();
        await checkUser.save();

        const token = jwt.sign(
            {
                userId: checkUser._id,
                email: checkUser.email,
            },
            process.env.JWT_SECRET,
            { expiresIn: "12h" }
        );

        res.cookie("token", token, {
            httpOnly: true,
            secure: true,
        });

        return res.status(200).send({
            success: true,
            message: "Login successful",
            token,
            user: {
                userId: checkUser._id,
                name: checkUser.name,
                email: checkUser.email,
                isAdmin: checkUser.isAdmin,
            }
        });

    } catch (error) {
        console.error("Login Error:", error.message);
        return res.status(500).send({
            success: false,
            message: "Login failed",
            error: error.message,
        });
    }
};

const userLogout = async (req, res) => {
    try {
        res.clearCookie("token", {
            httpOnly: true,
            secure: true
        })

        res.status(200).send({
            success: true,
            message: "Logout successful"
        });


    } catch (error) {
        console.log(error)
        res.status(500).send({
            success: false,
            message: "Logout failed",
            error: error.message
        });
    }
}

// ! Forgot and Reset Password
const forgotPassword = async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).send({ success: false, message: "Email is required" });
        }

        const user = await findByEmail({ email });

        if (user) {
            const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000); // 1 hour ago

            if (!user.otpRequestHistory) {
                user.otpRequestHistory = [];
            }

            // Filter out only the requests in the last 1 hour
            const recentOtpRequests = user.otpRequestHistory.filter(
                (timestamp) => timestamp > oneHourAgo
            );

            if (recentOtpRequests.length >= 5) {
                return res.status(429).send({ message: "Too many OTP requests. Please try again after some time." });
            }

            user.otpRequestHistory.push(new Date());
            await user.save();
        }
        else {
            return res.status(404).send({ success: false, message: "User does not exist" });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const passwordResetOtpExpiry = new Date(Date.now() + 5 * 60 * 1000); // 5 min expiry

        // Update existing user with OTP info
        user.passwordResetOtp = otp;
        user.passwordResetOtpExpiry = passwordResetOtpExpiry;
        await user.save();

        // Configure nodemailer
        const transporter = nodemailer.createTransport({
            service: "gmail",
            auth: {
                user: process.env.NODEMAILER_EMAIL,
                pass: process.env.NODEMAILER_PASSWORD,
            },
        });

        const mailOptions = {
            from: `"ZakDoc" <${process.env.NODEMAILER_EMAIL}>`,
            to: email,
            subject: "Reset Password - ZakDoc",
            text: `Your OTP to reset your password is: ${otp}. It will expire in 5 minutes.`,
        };

        await transporter.sendMail(mailOptions);

        res.status(200).send({
            success: true,
            message: "OTP sent to email successfully",
        });

    } catch (error) {
        console.error(error);
        res.status(500).send({
            success: false,
            message: "Server error",
            error: error.message,
        });
    }
};

const resetPassword = async (req, res) => {
    try {
        const { email, otp, newPassword } = req.body;

        if (!email || !otp || !newPassword) {
            return res.status(400).send({ success: false, message: "Email, OTP, and new password are required" });
        }

        const user = await findByEmail({ email });

        if (!user) {
            return res.status(404).send({ success: false, message: "User not found" });
        }

        if (user.passwordResetOtp !== otp) {
            return res.status(400).send({ success: false, message: "Invalid OTP" });
        }

        if (new Date() > user.passwordResetOtpExpiry) {
            return res.status(400).send({ success: false, message: "OTP has expired" });
        }

        // Hash new password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        // Update password and clear OTP
        user.password = hashedPassword;
        user.passwordResetOtp = undefined;
        user.passwordResetOtpExpiry = undefined;

        await user.save();

        res.status(200).send({ success: true, message: "Password reset successfully" });

    } catch (error) {
        console.error(error);
        res.status(500).send({
            success: false,
            message: "Server error",
            error: error.message,
        });
    }
};

//! Resend OTP
const resendOtp = async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).send({ message: "Email is required" });
    }

    const user = await findByEmail({ email });

    if (!user) {
        return res.status(404).send({ message: "User not found" });
    }

    // --- RATE LIMITING ---
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);

    if (!user.otpRequestHistory) {
        user.otpRequestHistory = [];
    }

    const recentOtpRequests = user.otpRequestHistory.filter(
        (timestamp) => timestamp > oneHourAgo
    );

    if (recentOtpRequests.length >= 5) {
        return res.status(429).send({ message: "Too many OTP requests. Please try again later." });
    }

    user.otpRequestHistory = [...recentOtpRequests, new Date()];

    let otp, expiry, subject, text;

    otp = Math.floor(100000 + Math.random() * 900000).toString();
    expiry = new Date(Date.now() + 5 * 60 * 1000); // 5 min expiry

    if (!user.isEmailVerified) {
        // It's for email verification
        user.emailVerificationOtp = otp;
        user.emailVerificationOtpExpiry = expiry;
        subject = "Email Verification - ZakDoc";
        text = `Your OTP for email verification is: ${otp}. It expires in 5 minutes.`;
    } else {
        // It's for password reset
        user.passwordResetOtp = otp;
        user.passwordResetOtpExpiry = expiry;
        subject = "Password Reset - ZakDoc";
        text = `Your OTP for password reset is: ${otp}. It expires in 5 minutes.`;
    }

    await user.save();

    // Send Email
    const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
            user: process.env.NODEMAILER_EMAIL,
            pass: process.env.NODEMAILER_PASSWORD,
        }
    });

    const mailOptions = {
        from: `"ZakDoc" <${process.env.EMAIL_USER}>`,
        to: email,
        subject,
        text,
    };

    try {
        await transporter.sendMail(mailOptions);
        res.status(200).send({ message: "OTP sent successfully" });
    } catch (error) {
        res.status(500).send({ message: "Failed to send OTP", error: error.message });
    }
};


module.exports = {
    userSignup, verifyOtpAndSignup, userLogin,
    userLogout,
    forgotPassword,
    resetPassword,
    resendOtp
}