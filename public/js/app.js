const tokenCircle = "auth0-demo";
const tokenId = "auth0-token";


var isCoreRunning = false;
/**
 * This function checks if the Circle service is running and connected.
 * It then creates the service configuration JSON, which is stored in
 * Circle. At the end of the function, the user is redirected to the
 * login page
 * 
 */
async function firstLogin() {

    if (!isCoreRunning) {
        showNotConnected();
        console.log("Not connected to Circle Service");
        return isCoreRunning;
    }
    // Get a cryptographically secure random string of variable length. 
    const state = randomString(32);
    const codeVerifier = randomString(64);

    // Get the sha256 digst of codeVerifier
    const codeChallenge = await sha256(codeVerifier).then(bufferToBase64UrlEncoded);

    // we need to store the state to validate the callback
    // and also the code verifier to send later
    sessionStorage.setItem(`login-code-verifier-${state}`, codeVerifier);
    const circleTopicData = await getCircleAndTopic();
    if (!circleTopicData) {
        return null;
    }

    // Object that stores the Auth0 configuration
    // for Circle Service login
    const serviceConfigurationJson = {
        "domain": AUTH0_DOMAIN,
        "client_id": AUTH0_CLIENT_ID,
        "code_challenge": codeChallenge,
        "code_challenge_method": "S256",
        "scope": "openid profile email offline_access",
        "state": state,
        "response_type": "code"
    }

    const configService = await Circle.configureService(circleTopicData.CircleId, 0, tokenCircle,
        JSON.stringify(serviceConfigurationJson));

    // Fetch the openid configuration for the issuer.
    // Look inside util.js
    const config = await getConfig();
    const authorizationEndpointUrl = new URL(config.authorization_endpoint);

    authorizationEndpointUrl.search = new URLSearchParams({
        redirect_uri: AUTH0_REDIRECT_URI,
        client_id: AUTH0_CLIENT_ID,
        response_type: 'code',
        scope: 'openid profile email offline_access',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        state: state
    });

    window.location.assign(authorizationEndpointUrl);
}

/**
*
* This function checks whether the service is running. After it 
* has determined all registered circles, it returns the ID of
* the first circle found.
* 
* @returns {String} with the first CircleId,
* 
*/
async function getCircleAndTopic() {

    if (!isCoreRunning) {
        showNotConnected();
        return isCoreRunning;
    }

    // Get all registered circles
    let allCircles = await Circle.enumCircles();

    if (!allCircles || !allCircles.Status.Result || !allCircles.CircleMeta || !allCircles.CircleMeta.length) {
        // We do not have a circle, lets create one.
        await createCircle(tokenCircle);
        allCircles = await Circle.enumCircles();
    }

    const firstCircle = allCircles.CircleMeta[0];
    // Returns the first Circle ID
    return {
        CircleId: firstCircle.CircleId,
    };
}


/**
 * This function checks is Circle Service is running
 * and creates the circle
 * 
 * @param {String} circleName 
 * @returns {String} return the circle
 */
async function createCircle(circleName) {

    if (!isCoreRunning) {
        showNotConnected();
        return isCoreRunning;
    }

    const circles = await Circle.createCircle(circleName, "");
    return circles;
}


/**
 * This function retrieves the token in the Circle service using the Circle
 * name and Token name specified in the parameters.
 * 
 * @param {String} tokenCircle 
 * @param {String} tokenName 
 * @returns String with the stored token 
 */
async function getCircleSavedToken(tokenCircle, tokenName) {
    const circleTopicData = await getCircleAndTopic();
    if (!circleTopicData) {
        return null;
    }

    const loginToService = await Circle.logintoService(circleTopicData.CircleId, 0, tokenCircle, tokenName);

    if (!loginToService || !loginToService.Status.Result || !loginToService.ServiceReturn) {
        return null;
    }

    return loginToService.ServiceReturn;
}


/**
 * This function stores the token in the Circle Service using the
 * Circle name and Token name specified in the parameters.
 * 
 * @param {String} tokenCircle Circle name
 * @param {String} auth0Token Token Name
 * @returns 
 */
async function saveTokenToCircle(tokenName, tokenValue) {

    if (!isCoreRunning) {
        showNotConnected();
        return isCoreRunning;
    }

    const circleTopicData = await getCircleAndTopic();

    if (!circleTopicData) {
        return false;
    }

    const saveToken = await Circle.storeToken(circleTopicData.CircleId, 0, tokenName, tokenValue);

    if (saveToken && saveToken.Status.Result) {
        return true;
    }
    return false;
}

/**
 * Get the Circle token from the /circle-token endpoint
 * Node.js backend
 * @returns {String} 
 */
async function getCircleToken() {
    let result = await fetch("/circle-token");
    let json = await result.json();
    return JSON.stringify(json.Token);
}

async function callCodesDecrypt(code1, code2) {
    // we will not a result as just logging the decrypted codes
    // on the server side.

    const req = { "code1": code1, "code2": code2 };
    console.log(req);
    console.log(JSON.stringify(req));
    let result = await fetch("/circle-decrypt", {
        method: "POST",
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(req)
    });

}

function showNotConnected() {
    console.log("Not connected to Circle Service");
}

/**
 * This function gets the token from the backend and authorizes
 * it by calling the "initialize" function.
 * 
 * @returns {Boolean}
 */
async function connectToCircle() {
    try {

        // Get the Circle Authorization token 
        let circleToken = await getCircleToken();
        circleToken = circleToken.replaceAll('"', '');

        // With the token, now you can initialize the CircleSDK 

        const result = await Circle.initialize(appKey, circleToken);

        if (result) {
            isCoreRunning = true;
        }

        return isCoreRunning;
    } catch (error) {
        console.log(error);
    }
}

/**
 * 
 * Check if it is a token, if not, redirect the user to the login page.
 * 
 */
async function tryToLogin() {

    if (!isCoreRunning) {
        await connectToCircle();
        if (!isCoreRunning) {
            return;
        }
    }

    try {
        let token = await getCircleSavedToken("auth0-demo", "auth0-token");

        if (token) {
            const tokenData = parseJwt(token);
            hideButtons();
            displayProfile(tokenData);
        } else {
            await firstLogin();
        }
    } catch (error) {
        console.log(error);
        if (error.status == 401) {
            connectToCircle();
            window.location.reload();
        }
    }
}

/**
 * Deletes the stored token and logs off Auth0
 */
async function reset() {
    if (!isCoreRunning) {
        await connectToCircle();
    }
    sessionStorage.clear();

    await saveTokenToCircle("auth0-token", "");
    window.tokenSet = "";
    window.verifier = "";
    window.location.href = "https://" + AUTH0_DOMAIN + "/v2/logout?client_id=" + AUTH0_CLIENT_ID + "&returnTo=http://localhost:3000/";
}


function parseJwt(token) {
    try {
        return JSON.parse(atob(token.split('.')[1]));
    } catch (e) {
        return null;
    }
}

/**
 * Get the user information from the 
 * token data and display it.
 * 
 * @param {
 * } tokenData 
 */
function displayProfile(tokenData) {
    hideButtons();

    $("#photo").attr("src", tokenData.picture);
    $("#email").html(tokenData.email);
    $("#user").html(tokenData.nickname);

    showHideLoader(false);

    setTitle("You are logged in as ");
    $(".profile").show();
    $("#logout").show();
    $("#reauth").show();
    $(".card").show();
}

/**
 * The function checks the URL for code and state parameters, exchanges the
 * authorization code for a token, stores the token in Circle, and displays 
 * the user information using the token
 * 
 */
(async function handleCallback() {

    const search = new URLSearchParams(window.location.search);

    if (!search.has('code')) { return; }

    $(".card").hide();
    $("#login").hide();

    hideButtons();
    setTitle("");

    const code = search.get('code');
    const state = search.get('state');
    const code_verifier = sessionStorage.getItem(`login-code-verifier-${state}`);

    if (!code_verifier) {
        console.error('unexpected state parameter');
        return;
    }

    const config = await getConfig();

    // exchange the authorization code for a tokenset
    const tokenSet = await fetch(config.token_endpoint, {
        method: 'POST',
        body: new URLSearchParams({
            // audience: API_AUDIENCE,
            client_id: AUTH0_CLIENT_ID,
            redirect_uri: AUTH0_REDIRECT_URI,
            grant_type: 'authorization_code',
            code_verifier,
            code,
        }),
        headers: new Headers({
            'Content-type': 'application/x-www-form-urlencoded; charset=UTF-8'
        })
    }).then(returnJson => returnJson.json());


    if (!isCoreRunning) {
        const isConneted = await connectToCircle();
    }

    // save the token in Circle Service    
    const isSaved = await saveTokenToCircle("auth0-token", tokenSet.refresh_token);

    // Parse the token to display user information.
    const tokenData = parseJwt(tokenSet.id_token);
    displayProfile(tokenData);
    $(".card").show();

    window.tokenSet = tokenSet;
    window.verifier = code_verifier;

    // remove the querystring from the url in the address bar
    removeHistory();
})();

/**
 * remove the querystring from the url in the address bar
 */
function removeHistory() {
    const url = new URL(window.location);
    url.search = '';
    window.history.pushState('', document.title, url);
}

/**
 * 
 * Locks the user and displays the screen for the user
 * enter the 2 codes.
 * 
 */

async function reAuthenticate() {
    if (!isCoreRunning) {
        await connectToCircle();
        if (!isCoreRunning) {
            return;
        }
    }

    const circleTopicData = await getCircleAndTopic();
    if (!circleTopicData) {
        return false;
    }

    // The number 2 means the number of codes to generate.
    const codes = await Circle.lockUser(circleTopicData.CircleId, 2);

    if (codes && codes.Status.Result && codes.EncryptedUnlockCodes.length > 1) {
        const code1 = codes.EncryptedUnlockCodes[0];
        const code2 = codes.EncryptedUnlockCodes[1];

        // call the backend to decrypt the codes with the private key
        callCodesDecrypt(code1, code2);

        // The codes must be decrypted with the primary key received and 
        // sent to the user, for example by e-mail and SMS
        console.log("Unlock code 1: " + code1);
        console.log("Unlock code 2: " + code2);

    }
    // displays the screen for entering the activation codes
    showEnterTwoCodes();
}

/**
 * This function checks if the service is running and 
 * if the user is locked out
 */
async function checkUserIsLocked() {

    if (!isCoreRunning) {
        await connectToCircle();
        if (!isCoreRunning) {
            return { "running": false, "locked": false };
        }
    }

    const circleTopicData = await getCircleAndTopic();
    if (!circleTopicData) {
        return false;
    }

    const userData = await Circle.whoAmI(circleTopicData.CircleId);
    if (userData) {
        return { "running": true, "locked": userData.Locked };
    }

}

/**
 * Unlock the user with the codes that the user has entered
 * into the enterCodesModal div
 * 
 */
async function unlockWithCodes() {

    if (!isCoreRunning) {
        await connectToCircle();
        if (!isCoreRunning) {
            return;
        }
    }

    const circleTopicData = await getCircleAndTopic();
    if (!circleTopicData) {
        return false;
    }

    const code1 = $("#code1").val();
    const code2 = $("#code2").val();
    const unlock = await Circle.unlockUser(circleTopicData.CircleId, [code1, code2]);

    if (unlock && unlock.Status.Result) {
        $("#enterCodesModal").modal('hide');
    }
}

function setTitle(text) {
    $("#title").html(text);
}

// hide the buttons
function hideButtons() {
    $("#login").hide();
    $("#logout").hide();
    $("#reauth").hide();
    $("#title").html("You are logget out ");
}

// show the user profile
function showCard(show) {
    $(".profile").hide();
    if (show) {
        $(".profile").show();
    }
}

// hide show the loader
function showHideLoader(show) {

    if (show) {
        $("#loadingModal").modal("show");
    } else {
        $("#loadingModal").modal("hide");
    }
}


// Show the DIV for users Users enter the unlock codes.
function showEnterTwoCodes() {
    setTitle("You are locked");
    $("#logout").hide();
    $("#enterCodesModal").modal("show");

}

// Lock the user and display the DIV for users to enter the unlock codes.
function hideProfileAndLock() {
    $(".profile").hide();
    reAuthenticate();
}

//Hide the DIV with codes input.
function hideProfileAndEnterTwoCodes() {
    showHideLoader(false);
    $(".profile").hide();
    showEnterTwoCodes();
}
