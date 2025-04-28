const mongoose = require('mongoose')

const DbConnection = async () => {
    try {
        await mongoose.connect(process.env.MONGO_URI)
        console.log("Database Connected Successfully")

    } catch (error) {
        console.log("Database connection Failed", error.message)
    }
}



module.exports = DbConnection 