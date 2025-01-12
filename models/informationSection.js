const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const InformationSectionSchema = new Schema({
    title: { type: String, required: true },
    subtitle: { type: String, required: false },
    content: { type: String, required: true },
    picture: { type: String, required: false },
    created_by: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    updated_by: { type: Schema.Types.ObjectId, ref: 'User', required: false },
    created_at: { type: Date, required: true },
    updated_at: { type: Date, required: false },
    active: { type: Boolean, default: true, required: false }
});

module.exports = mongoose.model('InformationSection', InformationSectionSchema);