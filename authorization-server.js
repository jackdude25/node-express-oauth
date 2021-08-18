const url = require("url");
const fs = require("fs")
const express = require("express")
const bodyParser = require("body-parser")
const jwt = require("jsonwebtoken")
const {
	randomString,
	containsAll,
	decodeAuthCredentials,
	timeout,
} = require("./utils")

const config = {
	port: 9001,
	privateKey: fs.readFileSync("assets/private_key.pem"),

	clientId: "my-client",
	clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
	redirectUri: "http://localhost:9000/callback",

	authorizationEndpoint: "http://localhost:9001/authorize",
}

const clients = {
	"my-client": {
		name: "Sample Client",
		clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
		scopes: ["permission:name", "permission:date_of_birth"],
	},
	"test-client": {
		name: "Test Client",
		clientSecret: "TestSecret",
		scopes: ["permission:name"],
	},
}

const users = {
	user1: "password1",
	john: "appleseed",
}

const requests = {}
const authorizationCodes = {}

let state = ""

const app = express()
app.set("view engine", "ejs")
app.set("views", "assets/authorization-server")
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

/*
Your code here
*/
app.get("/authorize", (req, res)=>{
	const clientId = req.query.client_id
	const client = clients[clientId]
	if (!client) {
		res.status(401).send("Error: client not authorized")
		return
	}
	if (
		typeof req.query.scope !== "string" ||
		!containsAll(client.scopes, req.query.scope.split(" "))
	) {
		res.status(401).send("Error: invalid scopes requested")
		return
	}
	const requestId = randomString()
	requests[requestId] = req.query
	res.render("login", {
		client,
		scope: req.query.scope,
		requestId,
	})

	app.post("/token", (req, res) => {
		let authCredentials = req.headers.authorization
		if (!authCredentials) {
			res.status(401).send("Error: not authorized")
			return
		}
		const { clientId, clientSecret } = decodeAuthCredentials(authCredentials)
		const client = clients[clientId]
		if (!client || client.clientSecret !== clientSecret) {
			res.status(401).send("Error: client not authorized")
			return
		}
		const code = req.body.code
		if (!code || !authorizationCodes[code]) {
			res.status(401).send("Error: invalid code")
			return
		}
		const { clientReq, userName } = authorizationCodes[code]
		delete authorizationCodes[code]
		const token = jwt.sign(
			{
				userName,
				scope: clientReq.scope,
			},
			config.privateKey,
			{
				algorithm: "RS256",
				expiresIn: 300,
				issuer: "http://localhost:" + config.port,
			}
		)
		res.json({
			access_token: token,
			token_type: "Bearer",
			scope: clientReq.scope,
		})
	})
	
})

app.post("/approve", (req, res) =>{
	un = req.body.userName;
	pw = req.body.password;
	if (!un || users[un] !== pw){
		res.status(401).send();
		return;
	}
	if (!requests[req.body.requestId]){
		res.status(401).send();
		return;
	}
	localReq = requests[req.body.requestId];
	delete requests[req.body.requestId];

	code = randomString();
	authorizationCodes[code] = {
		clientReq: localReq,
		userName: un
	}
	const redirectUri = url.parse(localReq.redirect_uri)
	redirectUri.query = {
		code,
		state: localReq.state,
	}
	res.redirect(url.format(redirectUri))
})


const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
})

// for testing purposes

module.exports = { app, requests, authorizationCodes, server }
