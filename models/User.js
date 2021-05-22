const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: [true, 'Please fill your name!']
    },
    email: {
        type: String,
        required: [true, 'Please provide an email'],
        unique: true,
        lowercase: true,
        validate: [validator.isEmail, 'Please provide a valid email']
    },
    emailToken: String,
    isVerified: Boolean,
    password: {
        type: String,
        required: [true, 'please provide a password!'],
        minlength: 8
    }
});

userSchema.pre('save', async function (next) {
    //only run this function if the password was modified , it will hash the password twice otherwise
    if (!this.isModified('password')) return next();

    this.password = await bcrypt.hash(this.password, 10)
});


module.exports = mongoose.model("User", userSchema);