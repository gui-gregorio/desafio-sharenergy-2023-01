const mongoose = require('mongoose')

const User = mongoose.model('User', {
    usuario: String,
    email: String,
    password: String
})


module.exports = User