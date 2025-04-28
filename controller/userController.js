const { Users } = require("../models/Users")
const { findByEmail, findById } = require("../services/userServices")
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
            return res.status(403).send({ message: "User is blocked by Admin" });
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

        const accessToken = jwt.sign(
            { userId: checkUser._id, email: checkUser.email },
            process.env.JWT_SECRET,
            { expiresIn: "15h" }  // Shorter lifespan
        );

        const refreshToken = jwt.sign(
            { userId: checkUser._id, email: checkUser.email },
            process.env.JWT_REFRESH_SECRET,
            { expiresIn: "7d" }  // Longer lifespan
        );

        checkUser.refreshToken = refreshToken;
        await checkUser.save();

        res.cookie("accessToken", accessToken, {
            httpOnly: true,
            secure: true,
            // maxAge: 15 * 60 * 1000, // 15 minutes
        });

        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: true,
            // maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        });

        return res.status(200).send({
            success: true,
            message: "Login successful",
            accessToken,
            refreshToken,
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
        const { refreshToken } = req.cookies;

        res.clearCookie("token", {
            httpOnly: true,
            secure: true,
            sameSite: "Strict",
        });

        res.clearCookie("refreshToken", {
            httpOnly: true,
            secure: true,
            sameSite: "Strict",
        });

        //  Remove refreshToken from DB
        if (refreshToken) {
            const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
            await Users.findByIdAndUpdate(decoded.userId, { $unset: { refreshToken: "" } });
        }

        return res.status(200).send({
            success: true,
            message: "Logout successful",
        });

    } catch (error) {
        console.log("Logout Error:", error.message);
        return res.status(500).send({
            success: false,
            message: "Logout failed",
            error: error.message,
        });
    }
};

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
            html: `
                <div style="font-family: Arial, sans-serif; padding: 20px; background-color: #f7f7f7;">
                    <div style="max-width: 600px; margin: auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0px 0px 10px rgba(0,0,0,0.1);">
                        <h2 style="color: #4CAF50;">Congratulations!</h2>
                        <p style="font-size: 16px; color: #555;">
                           Your OTP to reset your password is: <strong>${otp}</strong> It will expire in 5 minutes.
                        </p>
                        <p style="font-size: 14px; color: #999;">Thank you for contributing to ZakDoc.</p>
                        <hr style="margin: 20px 0;">
                        <p style="font-size: 12px; color: #ccc; text-align: center;">ZakDoc Team</p>
                    </div>
                </div>
            `,
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

//! Refresh Access Token 
const refreshAccessToken = async (req, res) => {
    try {
        const { refreshToken } = req.cookies;

        if (!refreshToken) {
            return res.status(401).send({ message: "Refresh Token required" });
        }

        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

        const user = await findById(decoded.userId);

        if (!user || user.refreshToken !== refreshToken) {
            return res.status(403).send({ message: "Invalid Refresh Token" });
        }

        const newAccessToken = jwt.sign(
            { userId: user._id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: "15m" }
        );

        res.cookie("accessToken", newAccessToken, {
            httpOnly: true,
            secure: true,
            maxAge: 15 * 60 * 1000,
        });

        return res.status(200).send({
            success: true,
            accessToken: newAccessToken,
        });

    } catch (error) {
        console.error("Refresh Token Error:", error.message);
        return res.status(403).send({ message: "Invalid or expired refresh token" });
    }
};


module.exports = {
    userSignup, verifyOtpAndSignup, userLogin,
    userLogout,
    forgotPassword,
    resetPassword,
    resendOtp,
    refreshAccessToken
}