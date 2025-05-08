const asyncHandler = require('express-async-handler');
const httpInstance = require('../services/httpInstance');

const axios = require('axios');
const qs = require('qs');

// @desc    Create a donation
// @route   POST /donations
// @access  Public
// @param   req: Request object
// req.body: {
//     name: String,
//     email: String,
//     amount: String (required, MXM),
//     card_name: String,
//     card_number: String,
//     card_expiration: String,
//    
// }
// @param   res: Response object

exports.create_donation = asyncHandler(async (req, res, next) => {
    res.setHeader('Content-Type', 'application/json');

    // Get authorization from PayPal
    const authorization = await axios({
        method: 'POST',
        url: 'https://api-m.sandbox.paypal.com/v1/oauth2/token',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': 'Basic ' + Buffer.from('AUv8rrc_P-EbP2E0mpb49BV7rFt3Usr-vdUZO8VGOnjRehGHBXkSzchr37SYF2GNdQFYSp72jh5QUhzG:' + process.env.PAYPAL_CLIENT_SECRET).toString('base64')
        },
        data: qs.stringify({
            grant_type: 'client_credentials'
        })
    }).catch((error) => {
        return res.status(500).send(error);
    });

    // Get the access token
    const accessToken = authorization.data['access_token'];

    // Create a payment order (donation)
    const order = await axios({
        method: 'POST',
        url: 'https://api-m.sandbox.paypal.com/v2/checkout/orders',
        headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
            'Prefer': 'return=representation'
        },
        data: {
            intent: 'CAPTURE',
            purchase_units: [
                {
                    amount: {
                        currency_code: 'MXN',
                        value: req.body['amount']
                    },
                    payee: {
                        email_address: req.body['email']
                    }
                }
            ]
        }
    }).catch((error) => {
        return res.status(500).send(error);
    });

    // Add a payment source to the payment order
    const paymentSource = await axios({
        method: 'POST',
        url: `https://api-m.sandbox.paypal.com/v2/checkout/orders/${order.data.id}/confirm-payment-source`,
        headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
            'Prefer': 'return=representation'
        },
        data: {
            payment_source: {
                card: {
                    'number': req.body.card_number,
                    'expiry': req.body.card_expiration
                }
            }
        }
    }).catch((error) => {
        if (error.response) {
            console.log('Error Response data: ', error.response.data);
            console.log('Error Response status: ', error.response.status);
            console.log('Error Response headers: ', error.response.headers);
            console.log('Error Response config: ', error.response.config);
            console.log('Error Response: ', error.response);
            console.log('Error Response details: ', error.response.data.details);
            return res.status(500).send(error.response.data);
        } else if (error.request) {
            console.log(error.request);
            return res.status(500).send('No response received from PayPal.');
        } else {
            console.log('Error', error.message);
            return res.status(500).send(error.message);
        }
    });

    // Add a payment source to the payment order
    // const paymentSource = await axios.post(`https://api-m.sandbox.paypal.com/v2/checkout/orders/${order.data.id}/confirm-payment-source`, 
    //     {
    //         payment_source: {
    //             card: {
    //                 number: req.body.card_number,
    //                 expiry: req.body.card_expiration
    //             }
    //         }
    //     },
    //     {
    //         headers: {
    //             'Authorization': `Bearer ${accessToken}`,
    //             'Content-Type': 'application/json',
    //             'Prefer': 'return=representation'
    //         }
    //     }
    // ).catch((error) => {
    //     return res.status(500).send(error);
    // });

    // Return the payment source
    return res.status(200).send(paymentSource.data);


    // Get authorization from PayPal
    // const authorization = await axios.post('https://api-m.sandbox.paypal.com/v1/oauth2/token', 
    //     { 
    //         grant_type: 'client_credentials',
    //         ignoreCache: true,
    //         return_authn_schemes: true,
    //         return_client_metadata: true,
    //         return_unconsented_scopes: true
    // 
    //     },
    //     {
    //         auth: {
    //             username: 'AUv8rrc_P-EbP2E0mpb49BV7rFt3Usr-vdUZO8VGOnjRehGHBXkSzchr37SYF2GNdQFYSp72jh5QUhzG',
    //             password: process.env.PAYPAL_CLIENT_SECRET
    //         },
    //         headers: {
    //             'Accept': '*/*',
    //             'Authorization': `Basic AUv8rrc_P-EbP2E0mpb49BV7rFt3Usr-vdUZO8VGOnjRehGHBXkSzchr37SYF2GNdQFYSp72jh5QUhzG:${process.env.PAYPAL_CLIENT_SECRET}`,
    //             'Content-Type': 'application/x-www-form-urlencoded',
    //             'Accept-Language': 'en_US'
    //         }
    //     } 
    // ).then((response) => {
    //     return res.status(200).send(response);
    // }).catch((error) => {
    //     return res.status(500).send(error);
    // });

    // Return the authorization token
    // res.status(200).json({ 
    //     success: true,
    //     data: authorization
    // });
    
});


exports.provide_payment_source = asyncHandler(async (req, res, next) => {

});


exports.make_donation = asyncHandler(async (req, res, next) => {

});
