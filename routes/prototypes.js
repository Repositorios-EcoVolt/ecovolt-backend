const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const PrototypeSchema = new Schema({
    name: { type: String, required: true },
    pictures: [{ type: String, required: false }],
    description: { type: String, required: false },

    // Generation
    begin_at: { type: Date, required: false }, // Date when begin the production of prototype
    end_at: { type: Date, required: false }, // Date when end the production of prototype

    // Units: km/h
    max_speed: { type: Number, required: false },

    // Dimentions (units: cm)
    large: { type: Number, required: false },
    width: { type: Number, required: false },
    high: { type: Number, required: false },

    weight: { type: Number, required: false },
    suspension: { type: String, required: false },

    // User accounting of modifications
    uploaded_at: { type: Date, required: true },
    uploaded_by: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    updated_at: { type: Date, required: false },
    updated_by: { type: Schema.Types.ObjectId, ref: 'User', required: false },

    // Active status
    active: { type: Boolean, default: true, required: true }
});

module.exports = mongoose.model('Prototype', PrototypeSchema);
