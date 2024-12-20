const mongoose = require("mongoose");
const Schema = mongoose.Schema;

// TO DO: Create a TTL index for the token field
const BlacklistedTokenSchema = new Schema({
    token: { type: String, required: true },
    expire_at: { type: Date, required: true }
});

module.exports = mongoose.model('BlacklistedToken', BlacklistedTokenSchema);
