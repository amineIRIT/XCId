// Import necessary modules
const path = require('path'); // Module for working with file paths. This is used to resolve paths of files and directories in a consistent way across different operating systems.
const express = require('express'); // Express.js framework, a minimal and flexible Node.js web application framework that provides a robust set of features to develop web and mobile applications.
const session = require('express-session'); // Middleware for Express applications to enable session support. It helps in storing session data on the server side and allows you to access the session data in your routes.
const Keycloak = require('keycloak-connect'); // A middleware for Express applications that allows you to integrate Keycloak for authentication and authorization. Keycloak is an open-source Identity and Access Management solution.
const fs = require('fs').promises; // Node.js File System module with Promise support
const fetch = require('node-fetch'); // A module that allows you to make HTTP requests using the Fetch API. It provides an interface for fetching resources across the network.

// Initialize the Express application
const app = express(); // Creates an instance of an Express application. This instance can be used to configure the web server, define routes, add middleware, etc.
const memoryStore = new session.MemoryStore(); // Creates a new instance of a memory store for sessions. This is a simple store for development purposes and not recommended for production.

// Configure the application to use EJS as the template engine
app.set('view engine', 'ejs'); // Sets EJS as the template engine for the application. EJS is a simple templating language that lets you generate HTML markup with plain JavaScript.
app.set('views', path.join(__dirname, '/view')); // Configures the directory where the template files are located. `__dirname` is a Node.js global variable that contains the path of the current directory.
app.use(express.static('static')); // Serves static files such as images, CSS files, and JavaScript files located in the 'static' directory.

// Configure the session
app.use(session({
    secret: 'KWhjV<T=-*VW<;cC5Y6U-{F.ppK+])Ub', // Secret key used to sign the session ID cookie. This can be any string and should be kept secure.
    resave: false, // Forces the session to be saved back to the session store, even if the session was never modified during the request.
    saveUninitialized: true, // Forces a session that is "uninitialized" to be saved to the store. A session is uninitialized when it is new but not modified.
    store: memoryStore, // Specifies the session store instance. Here, it's set to use the memory store created earlier.
}));


// Configure Keycloak
const keycloak = new Keycloak({
    store: memoryStore, // Specifies the session store that Keycloak should use. This allows Keycloak to store the session data in the same place as the express-session middleware.
});

//Initialize the Authorized CSP list array
var cspAuthList = {};

//Client secret between TRS and IDP
client_secret = 'XXX-ommitted-XXX'


// Keycloak middleware to handle authentication and route protection
app.use(keycloak.middleware({
    logout: '/logout', // Specifies the route that will be used for logging out users.
    admin: '/', // Specifies the base URL for the administration interface.
}));

// Main route redirecting to /home
app.get('/', (req, res) => res.redirect('/home')); // Defines a route for the root URL ('/') that redirects users to '/home'.

// Function to parse the JWT token
const parseToken = raw => {
    if (!raw || typeof raw !== 'string') return null; // Checks if the raw token is present and is a string. If not, returns null.

    try {
        raw = JSON.parse(raw); // Attempts to parse the raw token string as JSON.
        const token = raw.id_token ? raw.id_token : raw.access_token; // Extracts either the ID token or the access token from the parsed object.
        const content = token.split('.')[1]; // Splits the token into parts and takes the payload part (second part).

        return JSON.parse(Buffer.from(content, 'base64').toString('utf-8')); // Decodes the base64-encoded payload, parses it as JSON, and returns the resulting object.
    } catch (e) {
        console.error('Error while parsing token: ', e); // Logs an error if there was an issue parsing the token.
    }
};

async function getKeycloakToken(username, password, clientId, keycloakUrl) {
    const tokenEndpoint = `${keycloakUrl}/protocol/openid-connect/token`;
    const params = new URLSearchParams();

    params.append('client_id', clientId);
    params.append('username', username);
    params.append('password', password);
    params.append('grant_type', 'password');
    params.append('client_secret', client_secret);
    params.append('scope', 'openid');
    
    try {
        const response = await fetch(tokenEndpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: params,
        });
        
        
        if (!response.ok) {
            throw new Error(`Error fetching token: ${response.statusText}`);
        }

        const data = await response.json();
        return data.id_token; // or data for acceess_token
        
    } catch (error) {
        console.error('Error getting Keycloak token:', error);
        throw error; // Rethrow or handle as needed
    }
}


async function fetchCspTokens(csplist, username, password, kcUrl, res) {
    const cspTokens = {};

    for (const csp of csplist) {
        // csp is the client ID
        if (cspAuthList.includes(csp) ) {
            cspTokens[csp] = await getKeycloakToken(username, password, csp, kcUrl);
        }
        else {
            console.log('CSP', csp, 'not authorized.');
        }
    }

    res.json(JSON.stringify(cspTokens, null, 4));
}

function extractAttributeFromToken(idToken, attribute) {
    // Split the token into its parts (header, payload, signature)
    const parts = idToken.split('.');
    if (parts.length !== 3) {
        throw new Error('Invalid access token format');
    }
    
    // Decode the payload
    const payload = parts[1];
    const decodedPayload = Buffer.from(payload.replace(/_/g, '/').replace(/-/g, '+'), 'base64').toString('utf-8');
    
    // Parse the payload to JSON
    const payloadJSON = JSON.parse(decodedPayload);
    
    // Extract and return the specific attribute
    return payloadJSON[attribute];
}

// /home route protected by Keycloak, displays the homepage with user details
app.get('/trs', keycloak.protect(), (req, res, next) => {
    login_token=req.headers.authorization.split(' ')[1];
    cspAuthList = extractAttributeFromToken(login_token, "cspList").split(',').map(item => item.trim());
    const csplist = req.query.csplist.split(',');
    cspTokens = {};

    var username = 'XXX-ommitted-XXX';
    var password = 'XXX-ommitted-XXX';
    const kcUrl = 'XXX-ommitted-XXX';

    console.log('starting')
    fetchCspTokens(csplist, username, password, kcUrl, res); //responsible for the res.json() call
});


// /login route protected by Keycloak, redirects to /home
app.get('/login', keycloak.protect(), (req, res) => {
    return res.redirect('trs'); // Redirects the user to the '/home' route after successful login.
});

// /asset01 route with Keycloak access control to read asset-01
app.get('/asset01', keycloak.enforcer(['asset-01:read'], {
    resource_server_id: 'my-app'
}), (req, res) => {
    return res.status(200).end('success'); // Responds with a 200 status code and a 'success' message if the user has the 'asset-01:read' permission.
});

// /asset01/update route with Keycloak access control to write to asset-01
app.get('/asset01/update', keycloak.enforcer(['asset-01:write'], {
    resource_server_id: 'my-app'
}), (req, res) => {
    return res.status(200).end('success'); // Responds with a 200 status code and a 'success' message if the user has the 'asset-01:write' permission.
});

// Middleware to handle not found routes (404)
app.use((req, res, next) => {
    return res.status(404).end('Not Found'); // Responds with a 404 status code and a 'Not Found' message for any requests that do not match the defined routes.
});

// Middleware to handle errors
app.use((err, req, res, next) => {
    return res.status(req.errorCode ? req.errorCode : 500).end(req.error ? req.error.toString() : 'Internal Server Error'); // Responds with either the specific error code and message or a 500 status code and a generic 'Internal Server Error' message.
});

// Start the server on port 3000
const server = app.listen(3000, '127.0.0.1', () => {
    const host = server.address().address; // Retrieves the server's host address.
    const port = server.address().port; // Retrieves the server's port number.

    console.log('Application running at http://%s:%s', host, port); // Logs a message indicating where the application is running.
});
