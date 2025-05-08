const axios = require('axios');
const Config = require('../config');

const httpInstance = axios.create({
    baseURL: Config.API_URL,
    headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    }
});
