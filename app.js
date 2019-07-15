//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
// * * mongoose-encryption, MD5 and bcrypt constants - removed because we have switched to passport * * //
// const encrypt = require("mongoose-encryption");
// const md5 = require("md5");
// const bcrypt = require("bcrypt");
// const saltRounds = 10; // 10 are sufficient for 2019 and 2020

// * * passport packages * * ORDER IMPORTANT!
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
// note: the passport-local package will be use by passport-local-mongoose, so we don't need
//   to require it specifically here

// new constant called GoogleStrategy and it uses the passport-google-oauth20 package we installed
// and we are going to use it as a passport strategy
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
// npm package allowing us to use User.findOrCreate() in the Google and Facebook strategies
const findOrCreate = require("mongoose-findorcreate");


const app = express();

// console.log(process.env.API_KEY);

// express: this line serves images, CSS files and JavaScript files in a directory named 'public'
app.use(express.static("public"));
// sets the template engine to use to ejs
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

// ! important to specify the app.use() code for express-session BEFORE mongoose.connect() and
//   AFTER the app.use() code of express
// app.use(session()) sets up the session with some initial configurations
app.use(session({
  secret: "XXX",
  resave: false,
  saveUninitialized: true,
}));

// initialise passport - sets up passport so we can use it for authentication
app.use(passport.initialize()); // tells our app to use passport and to initialise it
app.use(passport.session()); // tells our app to use passport to deal with the session


// * use mongoose to connect to our mongoDB *
// specify the URL where our mongoDB database is located
// 27017 is the default port
// after the forward slash comes the name of our database, in this case userDB
mongoose.connect("mongodb://localhost:27017/userDB", {
  useNewUrlParser: true
});
// add the mongoose.set() code to get rid of the deprecation warning regarding index use
mongoose.set("useCreateIndex", true);

// ** set up a new user database **

// Step 1: Create a new schema so we can use mongoose-encryption
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);


// instead of using an encryption and a sign-in key, one can use a secret string
// *** HAS NOW MOVED TO THE .ENV FILE ***
// use that secret string to encrypt your database
// to the schema create above (l.28) add the encryption plug in and pass over our secret
//   string as a JavaScript object
// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] });
// Important: the encryption plugin has to be added to the schema before the model
//   is created because we pass in the userSchema as a parameter to create the User model
// *** PLUG IN FOR USER SCHEMA WAS REMOVED BECAUSE WE MOVED TO MD5 HASHING ***


// Step 2: Use the schema to set up a new User model
// as always, we speciy the name of our collection in the singular form: users --> User
const User = new mongoose.model("User", userSchema);

// passport local configurations
passport.use(User.createStrategy());

// passport code for serialising and deserialising; works with any type of authentication
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

// * GOOGLE *
// code for passport package google-oauth20
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    // deals with the Google Plus API deprecation (as of Dec 2018)
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
    // Now, when we use passport to authenticate users using Google OAuth
    // we are no longer retrieving their profile information from their Google+ account
    // but instead retrieve it from their user info (simply another endpoint on Google)
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);

    User.findOrCreate({
      googleId: profile.id
    }, function(err, user) {
      return cb(err, user);
    });
  }
));

// * FACEBOOK *
// code for the passport facebook authentication package
// configures the strategy
// http://www.passportjs.org/packages/passport-facebook/
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({
      facebookId: profile.id
    }, function(err, user) {
      return cb(err, user);
    });
  }
));


// render the homepage
app.get("/", function(req, res) {
  res.render("home");
});

// route for the path the "sign in with Google" button will hit up
app.get("/auth/google",
  //use passport to authenticate our user using the "google" strategy we set up above (ll. 97 ff.)
  // the code above helps Google recognise our app that we set up in the Google dashboard
  // And: When we git up Google, we tell them that what we want is the user's profile (incl. their email and their userId on Google)
  //   this ID we are going to identify them in the future
  passport.authenticate("google", {
    scope: ["profile"]
  }));

// this get request is made by Google when they redirect the user back to our website
app.get("/auth/google/secrets",
  passport.authenticate("google", {
    failureRedirect: "/login"
  }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect("/secrets");
  });

// Authenticating requests using Facebook:

// route for the path the "Sign In with Facebook" button will hit up
app.get("/auth/facebook",
  passport.authenticate("facebook"));

// get request made by Facebook when they redirect the user back to our website
app.get("/auth/facebook/secrets",
  passport.authenticate("facebook", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });



// render the login route
app.get("/login", function(req, res) {
  res.render("login");
});

// render the register route
app.get("/register", function(req, res) {
  res.render("register");
});

app.get("/secrets", function(req, res) {
  // if a user is already logged in, we want to simply render the secrets page
  // if not, we redirect them to the secrets page
  if (req.isAuthenticated()) {
    res.render("secrets");
  } else {
    res.redirect("/login");
  }
});

// get route for submissions of secrets from users
app.get("/submit", function(req, res){
  // if the user is logged in, i.e. req.isAuthenticated is true, they should be taken to submit.ejs
  // i.e. then we render the submit.ejs page so the user can submit a secret
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
})

app.get("/logout", function(req, res) {
  // de-authenticate the user and end the current session
  req.logout();
  res.redirect("/");
});



// catch post request from the form the user submits on the register homepage

app.post("/register", function(req, res) {

  // tap into the User model and call the register method on it
  // this method comes from the passport-local-mongoose package
  User.register({
    username: req.body.username
  }, req.body.password, function(err, user) {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });



  // * * * OLD CODE USING BCRYPT * * *

  // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
  //   // inside the callback function we now have access to the hash that we can store in our DB
  //   //   and use as our password (see line 88x)
  //
  //   // inside the callback function we create the user using the information that they passed over
  //   //   from the register page
  //   // in order to grab the data from the body of the post request we tap into the name variables
  //   //   of the username and password inputs
  //   const newUser = new User({
  //     email: req.body.username,
  //     // as the password we use the hash that we generated before
  //     password: hash
  //   });
  //
  //   // save that new user with their email and their hashed password into our database
  //   newUser.save(function(err) {
  //     if (err) {
  //       console.log(err)
  //     } else {
  //       res.render("secrets");
  //     }
  //   });
  // });

});







// catch the post request from the login route

app.post("/login", function(req, res) {

  // set up a new var called user, set up from our mongoose model
  const user = new User({
    // data drawn from the login form the user fills in
    username: req.body.username,
    password: req.body.password
  });

  // use passport to log in the user and authenticate them
  // the login method comes from passport
  // we need to pass in the new user that the user provided on our login page
  req.login(user, function(err) {
    if (err) {
      console.log(err);
    } else {
      // auhtenticate the user using their username and passwort
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });


  // * * * OLD CODE USING BCRYPT * * * //

  // // here we check whether we actually have a user in our database with the credentials they put in
  // // the credentials we are checking is the username and the password
  // const username = req.body.username;
  // const password = req.body.password;
  //
  // // check those constants against our database, i.e. look through our database and see if the name
  // // the user typed in is equal to one in the database
  // User.findOne({
  //   email: username
  // }, function(err, foundUser) {
  //   if (err) {
  //     console.log(err);
  //   } else {
  //     // if there is a user on our database with our email, we check whether the password in the
  //     //  database corresponds to the one the user typed in
  //     if (foundUser) {
  //
  //       // Load hash from your password DB.
  //       bcrypt.compare(password, foundUser.password, function(err, result) {
  //         if(result === true){
  //           res.render("secrets");
  //         }
  //       });
  //     }
  //   }
  // });
});







app.listen(3000, function() {
  console.log("Server is running on port 3000.");
});
