const express = require("express");
const router = express.Router()
const authMiddleware = require("../middleware/authMiddleware");

const { createArticle, 
    updateArticle, 
    deleteArticle, 
    restoreArticle,
    getUserSpecificArticles,
    searchArticles,
    filterArticlesByDate,
    filterArticlesByStatus,
    getTrashArticles
} = require("../controller/articleController");



router.post('/post-article', authMiddleware, createArticle)

router.put('/update-article/:id', authMiddleware, updateArticle)

router.delete('/delete-article/:id', authMiddleware, deleteArticle)

router.post('/restore-article/:id', authMiddleware, restoreArticle)

router.get('/all-articles', authMiddleware, getUserSpecificArticles)

router.get('/trash-articles', authMiddleware, getTrashArticles)

router.post('/search-articles', authMiddleware, searchArticles)

router.post('/filter-articles', authMiddleware, filterArticlesByDate)

router.post('/status-of-articles', authMiddleware, filterArticlesByStatus)



module.exports = router;

