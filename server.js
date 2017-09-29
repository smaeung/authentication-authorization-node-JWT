var express = require('express');
var app = express();
var bodyparser = require('body-parser');
var morgan = require('morgan');

var jwt = require('jsonwebtoken');
var config = require('./config');

// demo purpose only for user and password stored in configuration
// it should store in safe place such as database with hash password.
var users = config.users;

// set port number and JWT secret 
var port = process.env.PORT || 8080;
app.set('jwtSecret', config.secret);

app.use(bodyparser.urlencoded({ extended: false}));
app.use(bodyparser.json());

app.use(morgan('jwtlog'));

// API Route
app.get('/', function(req, res){
	res.send("please, use API at http://localhost:"+port +"/api/login");
});

// start server with port
app.listen(port);
console.log('API for JWT at http://localhost:'+ port);


// API Routes
var apiLoginRoutes = express.Router();
apiLoginRoutes.post('/login', function(req, res){
	
		var userAuthed = isUserAutheticated( users, req);	
		// if empty arry, it will throw error invalid authentication
		if(userAuthed){
			
			// at this time, it valid authenticated user.			
			// payload, secret key , options expiresIn seconds 
			// https://github.com/auth0/node-jsonwebtoken
			var _token = jwt.sign( 
				{ permission: userAuthed.permission },  // payload 
				config.secret,                     // secret 
				{ expiresIn: 120});	               // option to expired
				
			// send back to client with token for JWT
			res.json(
				{
					success: true, 
					message: 'Authentication is success',
					token: _token
				}
				);
		}else{
			res.json({ success: false, message: 'Authentication failed. the given user or password is not valid'});			
		}		
});
app.use('/api', apiLoginRoutes);

/**
 * authenticated user based on pre-defined user credentials
 * this is demo purpose only. 
 */
function isUserAutheticated(users, request){
	var validUser = users.filter( function(userElement){
		return userElement.user === request.body.user && 
			   userElement.password === request.body.password; 
	});
	// if no valid user, validUser should be empty array.
	return validUser[0];
}

// /api/users with GET permission in JWT token payload.
var apiUserRoutes = express.Router();
// check middleware to validate token first before invoking /api/users
apiUserRoutes.use( function(req, res, next){
	var bearIndex = 7;// bearer 
	// check header Authencation Bearer
	var token = req.headers['authorization'].slice(bearIndex);

	if(token){
		// let's verify the token with secret key
		// https://github.com/auth0/node-jsonwebtoken
		jwt.verify(token, config.secret, function(error, decoded){
			if(error){
				return res.json(
					{
						success: false, 
						message: 'the given token is invalid'
					}
				);
			}else{
				// token is valid and store it as req object with decoded
				req.decoded = decoded;
				console.log("decoded token:"+ decoded);
				// go to the next route API
				next();
			}
		});
	}else{
		// if no token then return an error
		return res.status(403).send({
			success: false,
			message: 'Invalid Token , no token provided'
		});
	}
	
});

// API /api/users with GET permission in the JWT token payload
apiUserRoutes.get('/users', function(req, res){
	var tokenPayload = req.decoded;
	// validation permission to access for API /users 
	if(tokenPayload.permission !== 'GET'){
		res.json({
			success: false,
			message: 'the given user does not have valid permission to access /api/users in the valid token'
		});
	}else{
		// return a list of user and password 
		res.json({
			success : true, 
			users : users
		});
	}
});
app.use('/api', apiUserRoutes);

