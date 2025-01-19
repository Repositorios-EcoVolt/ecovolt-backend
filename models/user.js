const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const UserSchema = new Schema({
    username: { type: String, unique: true, required: true },
    first_name: { type: String, required: true },
    last_name: { type: String, required: true },
    email: { type: String, required: true },
    password: { type: String, required: true },
    roles: [{ type: String, enum: ['admin', 'moderator', 'member'], required: true }],
    created_at: { type: Date, required: true },
    updated_at: { type: Date, required: false },
    last_login: { type: Date, required: false },
    verified: { type: Boolean, required: false },
    active: { type: Boolean, default: true, required: false }
});

UserSchema.virtual('full_name').get(function() {
    return this.first_name + ' ' + this.last_name;
});

module.exports = mongoose.model('User', UserSchema);