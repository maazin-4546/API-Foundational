const express = require('express')
const router = express.Router()

const { createUserByAdmin, adminLogin, adminLogout, getUsersByAdmin, getPaginatedUsers,
    filterUsersByDate,
    searchUsersByAdmin,
    blockOrUnblockUser,
    deleteUser,
    approveArticle,
    rejectArticle
} = require('../controller/adminController')

const isAdminMiddleware = require('../middleware/AdminMiddleware')


router.post("/signup", isAdminMiddleware, createUserByAdmin)

router.post("/login", adminLogin)

router.post("/logout", isAdminMiddleware, adminLogout)

router.post("/all-users", isAdminMiddleware, getUsersByAdmin)

// ------------------ Search and filter --------------------------

router.post("/users-per-page", isAdminMiddleware, getPaginatedUsers)

router.post("/users/filter-users-by-date", isAdminMiddleware, filterUsersByDate)

router.post("/search-users", isAdminMiddleware, searchUsersByAdmin);

// ------------------ Admin Actions --------------------------

router.patch("/block-user/:userId", isAdminMiddleware, blockOrUnblockUser);

router.patch("/delete-user/:userId", isAdminMiddleware, deleteUser);


// ------------- Articles --------------------

router.post("/approve-article/:id", isAdminMiddleware, approveArticle);

router.post("/reject-article/:id", isAdminMiddleware, rejectArticle);



module.exports = router