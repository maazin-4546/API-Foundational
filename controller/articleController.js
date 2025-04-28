const Articles = require("../models/Article");
const { findArticleById, findArticles, countArticles } = require("../services/articleServices");


const createArticle = async (req, res) => {
    try {
        const { title, content } = req.body;
        const userId = req.user._id; // from middleware

        if (!title || !content) {
            return res.status(400).send({ message: 'Title and content are required.' });
        }

        const newArticle = new Articles({
            title,
            content,
            authorId: userId,
        });

        await newArticle.save();

        res.status(201).send({
            success: true,
            message: 'Article created successfully!',
            article: newArticle,
        });

    } catch (error) {
        console.log("Logout Error:", error.message);
        return res.status(500).send({
            success: false,
            message: "Server Failed",
            error: error.message,
        });
    }
};

const updateArticle = async (req, res) => {
    try {
        const articleId = req.params.id;
        const { title, content } = req.body;
        const userId = req.user._id; // From authMiddleware

        const article = await findArticleById(articleId);

        if (!article) {
            return res.status(404).send({ message: 'Article not found.' });
        }

        // Check if the logged-in user is the author
        if (article.authorId.toString() !== userId.toString()) {
            return res.status(403).send({ message: 'Unauthorized to edit this article.' });
        }

        if (title) article.title = title;
        if (content) article.content = content;

        // Reset status to pending if edited (optional)
        article.status = 'pending';

        await article.save();

        res.status(200).send({
            success: true,
            message: 'Article updated successfully!',
            article,
        });

    } catch (error) {
        console.log("Error updating article:", error.message);
        return res.status(500).send({
            success: false,
            message: "Server Failed",
            error: error.message,
        });
    }
};


const deleteArticle = async (req, res) => {
    try {
        const articleId = req.params.id;
        const userId = req.user._id;

        const article = await findArticleById(articleId);

        if (!article) {
            return res.status(404).send({ message: "Article does not exist." });
        }

        if (article.authorId.toString() !== userId.toString()) {
            return res.status(403).send({ message: "Unauthorized to delete this article." });
        }

        // Soft delete
        article.isDeleted = true;
        article.deletedAt = new Date();
        await article.save();

        res.status(200).send({
            success: true,
            message: "Article deleted successfully!",
        });

    } catch (error) {
        console.error("Error deleting article:", error.message);
        return res.status(500).send({
            success: false,
            message: "Server failed.",
            error: error.message,
        });
    }
};



const restoreArticle = async (req, res) => {
    try {
        const articleId = req.params.id;
        const userId = req.user._id;

        const article = await findArticleById(articleId);

        if (!article) {
            return res.status(404).send({ message: 'Article not found.' });
        }

        if (article.authorId.toString() !== userId.toString()) {
            return res.status(403).send({ message: 'Unauthorized to restore this article.' });
        }

        if (!article.isDeleted) {
            return res.status(400).send({ message: 'Article is not deleted.' });
        }

        article.isDeleted = false;
        article.deletedAt = null;
        article.status = 'pending';
        await article.save();

        res.status(200).send({
            success: true,
            message: 'Article restored successfully!',
            article,
        });

    } catch (error) {
        console.error('Error restoring article:', error.message);
        return res.status(500).send({
            success: false,
            message: 'Server error. Please try again later.',
            error: error.message,
        });
    }
};


const getUserSpecificArticles = async (req, res) => {
    try {
        const userId = req.user._id;

        const query = {
            authorId: userId,
            isDeleted: false, // only active articles
        };

        const articles = await findArticles(query)

        res.status(200).send({
            success: true,
            count: articles.length,
            articles,
        });

    } catch (error) {
        console.error('Error fetching user articles:', error.message);
        return res.status(500).send({
            success: false,
            message: 'Server error. Please try again later.',
            error: error.message,
        });
    }
};

//! Search and filter

const searchArticles = async (req, res) => {
    try {
        const { title, author } = req.body;
        const userId = req.user._id;

        let query = {
            authorId: userId,
            isDeleted: false,
        };

        if (title) {
            query.title = { $regex: title, $options: 'i' }; // 'i' -> case-insensitive 
        }

        // Perform aggregation with $lookup to join articles with users for author name search
        const pipeline = [
            { $match: query },
            {
                $lookup: {
                    from: 'users',
                    localField: 'authorId',
                    foreignField: '_id',
                    as: 'author',
                },
            },
            { $unwind: '$author' },
            {
                $match: author
                    ? { 'author.name': { $regex: author, $options: 'i' } }
                    : {},
            },
            { $sort: { createdAt: -1 } },
        ];

        const articles = await Articles.aggregate(pipeline);

        res.status(200).send({
            success: true,
            count: articles.length,
            articles,
        });

    } catch (error) {
        console.error('Error searching articles:', error.message);
        return res.status(500).send({
            success: false,
            message: 'Server error. Please try again later.',
            error: error.message,
        });
    }
};


const filterArticlesByDate = async (req, res) => {
    try {
        const { startDate, endDate, page = 1, limit = 10 } = req.body;
        const userId = req.user._id;

        const filter = {
            authorId: userId,
            isDeleted: false,
        };

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

        const totalArticles = await countArticles(filter);

        const articles = await Articles.find(filter)
            .skip(skip)
            .limit(parseInt(limit))
            .sort({ createdAt: -1 });

        res.status(200).send({
            success: true,
            message: "User-specific articles filtered by date",
            articles,
            pagination: {
                totalArticles,
                page: parseInt(page),
                limit: parseInt(limit),
                totalPages: Math.ceil(totalArticles / limit),
            }
        });

    } catch (error) {
        console.log(error.message);
        res.status(500).send({
            success: false,
            message: "Server error while filtering articles",
            error: error.message
        });
    }
};



const filterArticlesByStatus = async (req, res) => {
    try {
        const { status, page = 1, limit = 10 } = req.body;
        const userId = req.user._id;

        const filter = {
            authorId: userId,
            isDeleted: false,
        };

        if (status) {
            filter.status = status;
        }

        const skip = (parseInt(page) - 1) * parseInt(limit);

        const totalArticles = await countArticles(filter);

        const articles = await Articles.find(filter)
            .skip(skip)
            .limit(parseInt(limit))
            .sort({ createdAt: -1 });

        res.status(200).send({
            success: true,
            message: "User-specific articles filtered by status",
            articles,
            pagination: {
                totalArticles,
                page: parseInt(page),
                limit: parseInt(limit),
                totalPages: Math.ceil(totalArticles / limit),
            }
        });

    } catch (error) {
        console.log(error.message);
        res.status(500).send({
            success: false,
            message: "Server error while filtering articles by status",
            error: error.message
        });
    }
};



const getTrashArticles = async (req, res) => {
    try {
        const { page = 1, limit = 10 } = req.query;
        const userId = req.user._id;

        const filter = {
            authorId: userId,
            isDeleted: true,
        };

        const skip = (parseInt(page) - 1) * parseInt(limit);

        const totalArticles = await countArticles(filter);

        const articles = await Articles.find(filter)
            .skip(skip)
            .limit(parseInt(limit))
            .sort({ createdAt: -1 });

        res.status(200).send({
            success: true,
            message: "Deleted articles (trash) fetched successfully",
            articles,
            pagination: {
                totalArticles,
                page: parseInt(page),
                limit: parseInt(limit),
                totalPages: Math.ceil(totalArticles / limit),
            }
        });

    } catch (error) {
        console.log(error.message);
        res.status(500).send({
            success: false,
            message: "Server error while fetching deleted articles",
            error: error.message
        });
    }
};






module.exports = {
    createArticle,
    updateArticle,
    deleteArticle,
    restoreArticle,
    getUserSpecificArticles,
    searchArticles,
    filterArticlesByDate,
    filterArticlesByStatus,
    getTrashArticles
}