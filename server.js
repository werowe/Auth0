const express = require('express');
const path = require('path');
const circleToken = require('./token-gen.js');

const app = express();
app.use(express.json());

app.get('/circle-token', async function (req, res) {
    const token = await circleToken();
    res.send(token);

});

app.post('/circle-decrypt', async function (req, res) {

    const unlockedCodes = await decryptUnlockCodes(req.body);
    //We just log the results in yout real application you should to send the codes
    //to the user by email or SMS to prove his identity.
    console.log(unlockedCodes);

});

app.use(express.static(path.join(__dirname, "public")));

app.listen(3000);
console.log('Listening on http://localhost:3000');