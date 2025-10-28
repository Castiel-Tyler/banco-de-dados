const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        require: true,
        unique: true,
        lowercase: true
    },
    password: {
        type: String,
        required: true,
        select: false
    }
})

userSchema.pre('save', async function(next) {
    if(!this.isModified('password')){
        return next();
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next()
})

userSchema.methods.matchPassword = async function(enterdPassword) {
    return await bcrypt.compare(enterdPassword, this.password)
}

module.exports = mongoose.model('User', userSchema)