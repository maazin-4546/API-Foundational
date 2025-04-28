const express = require('express')
const DbConnection = require('./database/DbConnection')
const cookieParser = require('cookie-parser');

const adminRoutes = require("./routes/adminRoutes")
const userRoutes = require("./routes/userRoutes")
const articleRoutes = require("./routes/articleRoutes")

require("dotenv").config();
const app = express()

const PORT = 5000

app.use(express.json())
app.use(cookieParser());

DbConnection()

app.use('/admin', adminRoutes)
app.use('/user', userRoutes)
app.use('/api', articleRoutes)


app.listen(PORT, () => {
    console.log(`Server is listening on port ${PORT}`)
})


