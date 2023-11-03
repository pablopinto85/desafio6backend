const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const userSchema = new Schema({
    username: String,
    password: {
        type: String,
        required: true
    },
    salt: {
        type: String,
        required: false
    }
});

const UserModel = mongoose.model('User', userSchema);
module.exports = UserModel;