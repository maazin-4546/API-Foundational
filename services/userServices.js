const { Users } = require("../models/Users")


const findByEmail = async (email) => {
    const user = await Users.findOne(email)
    return user
}

const findById = async (id) => {
    const user = await Users.findById(id)
    return user
}

const findUsers = (filter = {}, projection = "-password -__v") => {
    return Users.find(filter, projection);
};

const countDocuments = async () => {
    const user = await Users.countDocuments()
    return user
}

const findByIdAndUpdate = async (id, query = {}) => {
    const user = await Users.findByIdAndUpdate(id, query)
    return user
}


module.exports = {
    findByEmail,
    findById,
    findUsers,
    countDocuments,
    findByIdAndUpdate
}