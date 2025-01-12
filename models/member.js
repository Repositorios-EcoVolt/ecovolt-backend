const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const MemberSchema = new Schema({
    first_name: { type: String, required: true },
    last_name: { type: String, required: true },
    picture: { type: String, required: false },
    information: { type: String, required: true },
    joined_at: { type: Date, required: false },
    ended_at: { type: Date, required: false },
    uploaded_at: { type: Date, required: true },
    updated_at: { type: Date, required: false }
});

MemberSchema.virtual('full_name').get(function() {
    return this.first_name + ' ' + this.last_name;
});

MemberSchema.virtual('duration').get(function() {
    if (this.ended_at) {
        return this.ended_at - this.joined_at;
    } else {
        return new Date() - this.joined_at;
    }
});

MemberSchema.virtual('is_active').get(function() {
    return this.ended_at? false:true;
});

module.exports = mongoose.model('Member', MemberSchema);