const express = require('express')
const DbConnection = require('./database/DbConnection')

const adminRoutes = require("./routes/adminRoutes")
const userRoutes = require("./routes/userRoutes")

require("dotenv").config();
const app = express()

const PORT = 5000

app.use(express.json())


DbConnection()

app.use('/admin', adminRoutes)
app.use('/user', userRoutes)


app.listen(PORT, () => {
    console.log(`Server is listening on port ${PORT}`)
})


