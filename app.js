//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
// mongoose-encryption removed because we have switched to MD5
// const encrypt = require("mongoose-encryption");
// const md5 = require("md5");
const bcrypt = require("bcrypt");
const saltRounds = 10; // for 2019 and 2020


const app = express();

// console.log(process.env.API_KEY);

// express: this line serves images, CSS files and JavaScript files in a directory named 'public'
app.use(express.static("public"));
// sets the template engine to use to ejs
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

// * use mongoose to connect to our mongoDB *
// specify the URL where our mongoDB database is located
// 27017 is the default port
// after the forward slash comes the name of our database, in this case userDB
mongoose.connect("mongodb://localhost:27017/userDB", {
  useNewUrlParser: true
});

// ** set up a new user database **

// Step 1: Create a new schema so we can use mongoose-encryption
const userSchema = new mongoose.Schema({
  email: String,
  password: String
});

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




// render the homepage
app.get("/", function(req, res) {
  res.render("home");
});

// render the login route
app.get("/login", function(req, res) {
  res.render("login");
});

// render the register route
app.get("/register", function(req, res) {
  res.render("register");
});

// catch post request from the form the user submits on the register homepage

app.post("/register", function(req, res) {

  bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
    // inside the callback function we now have access to the hash that we can store in our DB
    //   and use as our password (see line 88x)

    // inside the callback function we create the user using the information that they passed over
    //   from the register page
    // in order to grab the data from the body of the post request we tap into the name variables
    //   of the username and password inputs
    const newUser = new User({
      email: req.body.username,
      // as the password we use the hash that we generated before
      password: hash
    });

    // save that new user with their email and their hashed password into our database
    newUser.save(function(err) {
      if (err) {
        console.log(err)
      } else {
        res.render("secrets");
      }
    });
  });

});







// catch the post request from the login route

app.post("/login", function(req, res) {
  // here we check whether we actually have a user in our database with the credentials they put in
  // the credentials we are checking is the username and the password
  const username = req.body.username;
  const password = req.body.password;

  // check those constants against our database, i.e. look through our database and see if the name
  // the user typed in is equal to one in the database
  User.findOne({
    email: username
  }, function(err, foundUser) {
    if (err) {
      console.log(err);
    } else {
      // if there is a user on our database with our email, we check whether the password in the
      //  database corresponds to the one the user typed in
      if (foundUser) {

        // Load hash from your password DB.
        bcrypt.compare(password, foundUser.password, function(err, result) {
          if(result === true){
            res.render("secrets");
          }
        });
      }
    }
  });
});







app.listen(3000, function() {
  console.log("Server is running on port 3000.");
});
