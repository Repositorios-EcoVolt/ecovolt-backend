const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const GalleryPhotoSchema = new Schema({
    name: { type: String, required: false }, 
    picture: { type: String, required: true },
    description: { type: String, required: false },
    uploaded_at: { type: Date, required: true },
    uploaded_by: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    updated_at: { type: Date, required: false },
    updated_by: { type: Schema.Types.ObjectId, ref: 'User', required: false },
    active: { type: Boolean, default: true, required: true }
});

// Name appears in alt <img alt="name">
GalleryPhotoSchema.virtual('alt').get(function() {
    return this.name;
});

module.exports = mongoose.model('GalleryPhoto', GalleryPhotoSchema);