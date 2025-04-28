const Articles = require("../models/Article")

const findArticleById = async (id) => {
    const article = await Articles.findById(id)
    return article
}

const findArticles = async (query) => {
    const article = await Articles.find(query).sort({ createdAt: -1 });
    return article
}

const countArticles = async (query) => {
    const article = await Articles.find(query).countDocuments();
    return article
}



module.exports = {
    findArticleById,
    findArticles,
    countArticles
}