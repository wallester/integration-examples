const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const request = require("request");
const fs = require("fs");

// Replace this with the actual issuer ID you've got from Wallester
const issuer = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";

// Replace this with the actual audience ID you've got from Wallester
const audience = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";

// Replace this with actual Wallester API URL
const apiURL = "http://xxx.wallester.eu/v1/test/ping";

const algorithm = "RS256";

const privateKey = fs.readFileSync("../../keys/example_private");
const wallesterPublicKey = fs.readFileSync("../../keys/example_wallester_public");

const subject = "api-request";
const requestBody = JSON.parse('{"message":"ping"}');

main();

function main() {
    var token = createToken(privateKey, requestBody);

    doRequest(requestBody, token, wallesterPublicKey,
        function (err, res, body) {
            if (err) {
                console.error("Failed to make POST request:", err);
                return;
            }

            try {
                token = res.headers.authorization.replace("Bearer ", "");
                verifyResponse(body, token, wallesterPublicKey);
                console.log("Response is trusted!");
            } catch (e) {
                console.log("Response is not trusted:", e);
            }
        });
}

function doRequest(requestBody, token, wallesterPublicKey, callback) {
    console.log("Request JWT token:", token);
    console.log(requestBody);
    console.log();

    request.post({
        url: apiURL,
        json: true,
        headers: {
            "Content-Type": "application/json",
            Authorization: "Bearer " + token
        },
        body: requestBody
    }, function (err, res, body) {
        if (err || res.statusCode !== 200) {
            return callback(err || {statusCode: res.statusCode});
        }
        callback(null, res, body);
    });
}

function createToken(privateKey, requestBody) {
    var payload = {
        iss: issuer,
        aud: audience,
        sub: subject,
        rbh: calculateHash(requestBody)
    };

    return jwt.sign(payload, privateKey, {algorithm: algorithm, expiresIn: "1m"});
}

function verifyResponse(responseBody, token, publicKey) {
    console.log("Response JWT token:", token);
    console.log(responseBody);
    console.log();

    jwt.verify(token, publicKey, {algorithm: "RS256"},
        function (err, decoded) {
            if (err) {
                throw err;
            }

            if (responseBody.message !== "pong") {
                throw new Error("Invalid response body: " + responseBody.message);
            }

            if (decoded.rbh !== calculateHash(responseBody)) {
                throw new Error("Invalid response body hash");
            }
        });
}

function calculateHash(body) {
    var buf = new Buffer.from(JSON.stringify(body));
    return crypto.createHash("sha256").update(buf).digest("base64");
}