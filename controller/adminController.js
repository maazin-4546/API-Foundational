const { Users } = require("../models/Users");
const jwt = require("jsonwebtoken")
const bcrypt = require('bcryptjs');
const nodemailer = require("nodemailer")

const { findByEmail, findUsers, countDocuments, findById } = require("../services/userServices");
const { findArticleById } = require("../services/articleServices");


const createUserByAdmin = async (req, res) => {
    try {
        if (!req.user.isAdmin) {
            return res.status(403).send({ message: "Only admins can create users" });
        }

        const { name, email, password, isAdmin = false } = req.body;

        const existing = await findByEmail({ email });
        if (existing) return res.status(400).send({ message: "User already exists" });

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new Users({
            name,
            email,
            password: hashedPassword,
            isAdmin
        });

        await newUser.save();

        res.status(201).send({ message: "User created successfully", user: newUser });
    } catch (error) {
        res.status(500).send({ message: "Something went wrong", error });
    }
};

const adminLogin = async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).send({ message: "Both email and password are required" })
        }

        const checkUser = await findByEmail({ email })
        if (!checkUser) {
            return res.status(401).send({ message: "Invalid credentials" })
        }

        if (!checkUser.isAdmin) {
            return res.status(401).send({ message: "Unauthorized" })
        }

        const checkPassword = await bcrypt.compare(password, checkUser.password)
        if (!checkPassword) {
            return res.status(401).send({ message: "Invalid credentials" });
        }

        const token = jwt.sign({
            userId: checkUser._id,
            email: checkUser.email,
            isAdmin: checkUser.isAdmin
        },
            process.env.JWT_SECRET,
            { expiresIn: "12h" })

        res.cookie("token", token, {
            httpOnly: true,
            secure: true
        });

        res.status(200).send({
            success: true,
            message: "login success",
            token,
            user: { email }
        })


    } catch (error) {
        console.log(error)
        res.status(500).send({
            success: false,
            message: "Login failed",
            error: error.message
        });
    }
}

const adminLogout = async (req, res) => {
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
        res.status(500).send({
            success: false,
            message: "logout failed",
            error: error.message
        })
    }
}

const getUsersByAdmin = async (req, res) => {
    try {
        if (!req.user.isAdmin) {
            return res.status(403).send({ message: "Only admins can fetch users list" });
        }

        const users = await Users.find({}, "-password -__v")
        res.status(200).send({
            success: true,
            message: "All users fetched successfully",
            users
        });

    } catch (error) {
        console.log(error)
        res.status(500).send({
            success: false,
            message: "can not get users data",
            error: error.message
        })
    }
}

// ! Pagination 
const getPaginatedUsers = async (req, res) => {
    try {
        if (!req.user.isAdmin) {
            return res.status(403).send({ message: "Only admins can fetch users list" });
        }

        const page = parseInt(req.body.page) || 1;
        const limit = parseInt(req.body.limit) || 10;
        const skip = (page - 1) * limit;

        const totalUsers = await countDocuments();
        const users = await findUsers()
            .skip(skip)
            .limit(limit)
            .sort({ createdAt: -1 }); // Newest first

        res.status(200).send({
            success: true,
            message: "Users fetched successfully",
            page,
            totalPages: Math.ceil(totalUsers / limit),
            totalUsers,
            users
        });

    } catch (error) {
        console.log(error);
        res.status(500).send({
            success: false,
            message: "Failed to fetch paginated users",
            error: error.message
        });
    }
};

//! Filter by date
const filterUsersByDate = async (req, res) => {
    try {
        if (!req.user.isAdmin) {
            return res.status(403).send({ message: "Only admins can fetch" });
        }

        const { startDate, endDate, page = 1, limit = 10 } = req.body;

        const filter = {};

        if (startDate && endDate) {
            const start = new Date(startDate);
            const end = new Date(endDate);
            end.setDate(end.getDate() + 1);
            filter.createdAt = {
                $gte: start,
                $lt: end
            };
        }

        const skip = (parseInt(page) - 1) * parseInt(limit);
        const totalUsers = await countDocuments(filter);

        const users = await findUsers(filter, "-password -__v")
            .skip(skip)
            .limit(parseInt(limit))
            .sort({ createdAt: -1 });

        res.status(200).send({
            success: true,
            message: "Users filtered by date",
            users,
            pagination: {
                totalUsers,
                page: parseInt(page),
                limit: parseInt(limit),
                totalPages: Math.ceil(totalUsers / limit),
            }
        });

    } catch (error) {
        res.status(500).send({
            success: false,
            message: "Server error while filtering users",
            error: error.message
        });
    }
};

//! Search users
const searchUsersByAdmin = async (req, res) => {
    try {
        const { search, isEmailVerified, page = 1, limit = 10 } = req.body;

        const query = {};

        // Search by name or email (case-insensitive)
        if (search) {
            query.$or = [
                { name: { $regex: search, $options: "i" } },
                { email: { $regex: search, $options: "i" } }
            ];
        }

        // Optional filter by verification status
        if (typeof isEmailVerified === "boolean") {
            query.isEmailVerified = isEmailVerified;
        }

        const skip = (parseInt(page) - 1) * parseInt(limit);

        const total = await countDocuments(query);
        const users = await findUsers(query, "-password -__v")
            .skip(skip)
            .limit(parseInt(limit))
            .sort({ createdAt: -1 });

        res.status(200).send({
            success: true,
            message: "User search successful",
            data: users,
            pagination: {
                totalUsers: total,
                page: parseInt(page),
                totalPages: Math.ceil(total / limit),
                limit: parseInt(limit),
            }
        });

    } catch (error) {
        res.status(500).send({
            success: false,
            message: "Server error while searching users",
            error: error.message
        });
    }
};

//! block user
const blockOrUnblockUser = async (req, res) => {
    try {
        if (!req.user.isAdmin) {
            return res.status(403).send({ message: "Only admins can change status" });
        }

        const userId = req.params.userId;
        const { block } = req.body;

        if (typeof block !== "boolean") {
            return res.status(400).send({ message: "Block status must be true or false" });
        }

        const user = await findById(userId);
        if (!user) {
            return res.status(404).send({ message: "User not found" });
        }

        user.isBlocked = block;
        await user.save();

        res.status(200).send({
            success: true,
            message: `User has been ${block ? "blocked" : "unblocked"} successfully.`,
            user: {
                _id: user._id,
                name: user.name,
                email: user.email,
                isBlocked: user.isBlocked,
            }
        });

    } catch (error) {
        res.status(500).send({
            success: false,
            message: "Something went wrong while blocking/unblocking user",
            error: error.message
        });
    }
};

//! delete user
const deleteUser = async (req, res) => {
    try {
        if (!req.user.isAdmin) {
            return res.status(403).send({ message: "Only admins can change status" });
        }

        const userId = req.params.userId;
        const { isUserDeleted } = req.body;

        if (typeof isUserDeleted !== "boolean") {
            return res.status(400).send({ message: "Delete status must be true or false" });
        }

        const user = await findById(userId);
        if (!user) {
            return res.status(404).send({ message: "User not found" });
        }

        user.isDeleted = isUserDeleted;
        await user.save();

        res.status(200).send({
            success: true,
            message: `User has been ${isUserDeleted ? "deleted" : "undeleted"} successfully.`,
            user: {
                _id: user._id,
                name: user.name,
                email: user.email,
                isDeleted: user.isDeleted,
            }
        });

    } catch (error) {
        res.status(500).send({
            success: false,
            message: "Something went wrong while deleting/undeleting user",
            error: error.message
        });
    }
};


// ------------- Articles --------------------


const approveArticle = async (req, res) => {
    try {
        const articleId = req.params.id;
        const { accessToken } = req.cookies

        if (!req.user.isAdmin) {
            return res.status(403).send({ message: 'You do not have permission to approve articles.' });
        }

        const article = await findArticleById(articleId);

        if (!article) {
            return res.status(404).send({ message: 'Article not found.' });
        }

        // Check if the article is already approved
        if (article.status === 'approved') {
            return res.status(400).send({ message: 'Article is already approved.' });
        }

        // Update the status to 'approved'
        article.status = 'approved';
        article.updatedAt = new Date();

        await article.save();

        const decoded = jwt.verify(accessToken, process.env.JWT_SECRET);
        const email = decoded.email

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
            subject: "Article Approval Notification",
            html: `
                <div style="font-family: Arial, sans-serif; padding: 20px; background-color: #f7f7f7;">
                    <div style="max-width: 600px; margin: auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0px 0px 10px rgba(0,0,0,0.1);">
                        <h2 style="color: #4CAF50;">Congratulations!</h2>
                        <p style="font-size: 16px; color: #555;">
                            Your article with ID <strong>${article._id}</strong> has been <span style="color: green; font-weight: bold;">approved</span> by the admin.
                        </p>
                        <p style="font-size: 14px; color: #999;">Thank you for contributing to ZakDoc. Keep writing great articles!</p>
                        <hr style="margin: 20px 0;">
                        <p style="font-size: 12px; color: #ccc; text-align: center;">ZakDoc Team</p>
                    </div>
                </div>
            `,
        };


        await transporter.sendMail(mailOptions);

        res.status(200).send({
            success: true,
            message: 'Article approved successfully!',
            article,
        });

    } catch (error) {
        console.error('Error approving article:', error.message);
        return res.status(500).send({
            success: false,
            message: 'Server error. Please try again later.',
            error: error.message,
        });
    }
};


const rejectArticle = async (req, res) => {
    try {
        const articleId = req.params.id;
        const { accessToken } = req.cookies

        if (!req.user.isAdmin) {
            return res.status(403).send({ message: 'You do not have permission to reject articles.' });
        }

        const article = await findArticleById(articleId);

        if (!article) {
            return res.status(404).send({ message: 'Article not found.' });
        }

        // Check if the article is already rejected
        if (article.status === 'rejected') {
            return res.status(400).send({ message: 'Article is already rejected.' });
        }

        // Update the status to 'rejected'
        article.status = 'rejected';
        article.updatedAt = new Date();

        await article.save();

        const decoded = jwt.verify(accessToken, process.env.JWT_SECRET);
        const email = decoded.email

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
            subject: "Article Rejection Notification",
            html: `
                <div style="font-family: Arial, sans-serif; padding: 20px; background-color: #f7f7f7;">
                    <div style="max-width: 600px; margin: auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0px 0px 10px rgba(0,0,0,0.1);">
                        <h2 style="color: #4CAF50;">Sorry.</h2>
                        <p style="font-size: 16px; color: #555;">
                            Your article with ID <strong>${article._id}</strong> has been <span style="color: green; font-weight: bold;">rejected</span> by the admin.
                        </p>
                        <p style="font-size: 14px; color: #999;">Thank you for contributing to ZakDoc. Keep writing great articles!</p>
                        <hr style="margin: 20px 0;">
                        <p style="font-size: 12px; color: #ccc; text-align: center;">ZakDoc Team</p>
                    </div>
                </div>
            `,
        };


        await transporter.sendMail(mailOptions);

        res.status(200).send({
            success: true,
            message: 'Article rejected successfully!',
            article,
        });

    } catch (error) {
        console.error('Error approving article:', error.message);
        return res.status(500).send({
            success: false,
            message: 'Server error. Please try again later.',
            error: error.message,
        });
    }
};



module.exports = {
    createUserByAdmin, adminLogin, adminLogout,
    getUsersByAdmin,
    getPaginatedUsers,
    filterUsersByDate,
    searchUsersByAdmin,
    blockOrUnblockUser,
    deleteUser,
    approveArticle,
    rejectArticle
}