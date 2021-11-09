const dotenv = require('dotenv');
const axios = require('axios');
const crypto = require("crypto");
dotenv.config();


var encryptData = function (dataToEncrypt) {
    return crypto.createHmac('sha256', process.env.SECRET.trim()).update(dataToEncrypt).digest('base64');
}

/**
 *  Generate the token using Circle's credentials
 * 
 * @returns {String} 
 */

async function circleToken() {
    let timeStamp = Math.floor(Date.now() / 1000);
    let urlParameters = `customerId=${process.env.CUSTOMER_ID}&appKey=${process.env.APPKEY}&endUserId=${process.env.USER_ID}`;
    urlParameters += '&nonce=' + timeStamp;

    let signature = encryptData(urlParameters);

    config = {
        baseURL: process.env.API_URL,
        headers: 'Content-Type: application/json',
        data: urlParameters + '&signature=' + signature
    }
    try {
        const ret = await axios.get("https://api.gocircle.ai/api/token?" + urlParameters + '&signature=' + signature);
        const cleaned = JSON.parse(ret.data.toString().replace(/\r\n/g, ""));
        return cleaned;

    } catch (error) {
        console.log(error);
        return null;
    }

}

module.exports = circleToken;