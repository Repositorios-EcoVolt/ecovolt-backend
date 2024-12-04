// --------------------------------------------------------------
// Description: MongoDB database connection
// --------------------------------------------------------------

// Load environment variables
require("dotenv").config(); 
const mongoose = require("mongoose");

mongoose.set("strictQuery", false);
const mongoDB = process.env.MONGO_DB;

// Connect to the database
async function main() {
    await mongoose.connect(mongoDB);
}

module.exports = main;