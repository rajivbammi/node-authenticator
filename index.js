let express = require('express')
let morgan = require('morgan')
let bodyParser = require('body-parser')
let cookieParser = require('cookie-parser')
let session = require('express-session')
let passport = require('passport')
let LocalStrategy = require('passport-local').Strategy
let nodeifyit = require('nodeifyit')
let crypto = require('crypto')
let SALT = 'CodePathHeartNodeJS'
// Add connect-flash middleware to index.js
let flash = require('connect-flash')
let User = require('./user')
let mongoose = require('mongoose')
mongoose.connect('mongodb://127.0.0.1:27017/authenticator')

  // Add in-memory user before app.listen()
let user = {
  email: 'foo@foo.com',
   password: crypto.pbkdf2Sync('abcd', SALT, 4096, 512, 'sha256').toString('hex')
}

// Will allow crypto.promise.pbkdf2(...)
require('songbird')

const NODE_ENV = process.env.NODE_ENV
const PORT = process.env.PORT || 8000

let app = express()

app.use(flash())
// Read cookies, required for sessions
app.use(cookieParser('ilovethenodejs'))
  // Get POST/PUT body information (e.g., from html forms like login)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({
    extended: true
  }))

  // In-memory session support, required by passport.session()
app.use(session({
    secret: 'ilovethenodejs',
    resave: true,
    saveUninitialized: true
  }))
  // Use the passport middleware to enable passport
app.use(passport.initialize())
  // Enable passport persistent sessions
app.use(passport.session())


passport.use('local', new LocalStrategy({
    // Use "email" field instead of "username"
    usernameField: 'email',
    // We'll need this later
    failureFlash: true
}, nodeifyit(async (email, password) => {
    var tmpuser
    if (tmpuser = await User.promise.findOne({email}))  {
       //var tmpuser = await User.promise.findOne({email})
       let passwordHash = await crypto.promise.pbkdf2(password, SALT, 4096, 512, 'sha256')
       
       if (passwordHash.toString('hex') !== tmpuser.password) {
         return [false, {message: 'Invalid password'}]
       }
      return tmpuser
    } else {
       return [false, {message: 'Invalid username'}]
   }
}, {spread: true})))


passport.use('local-signup', new LocalStrategy({
   // Use "email" field instead of "username"
   usernameField: 'email'
}, nodeifyit(async (email, password) => {
    email = (email || '').toLowerCase()
    // Is the email taken?
    if (await User.promise.findOne({email})) {
        return [false, {message: 'That email is already taken.'}]
    }

    // create the user
    let user = new User()
    user.email = email
    // Use a password hash instead of plain-text
    user.password = (await crypto.promise.pbkdf2(password, SALT, 4096, 512, 'sha256')).toString('hex')
    return await user.save()
}, {spread: true})))


// Use email since id doesn't exist
passport.serializeUser(nodeifyit(async (user) => user.email))
//passport.deserializeUser(nodeifyit(async (id) => user))
passport.deserializeUser(nodeifyit(async (email) => {
    return await User.findOne({email}).exec()
}))

app.set('view engine', 'ejs')

// start server 
app.listen(PORT, () => console.log(`Listening @ http://127.0.0.1:${PORT}`))

app.get('/', (req, res) => {
    res.render('index.ejs', {message: req.flash('error')})
})

app.post('/login', passport.authenticate('local', {
    successRedirect: '/profile',
    failureRedirect: '/',
    failureFlash: true
}))
// process the signup form
app.post('/signup', passport.authenticate('local-signup', {
    successRedirect: '/profile',
    failureRedirect: '/',
    failureFlash: true
}))

function isLoggedIn(req, res, next) {
    if (req.isAuthenticated()) return next()
    res.redirect('/')
}
app.get('/profile', isLoggedIn, (req, res) => res.render('profile.ejs', {user: req.user}))

app.get('/logout', function(req, res){
  req.logout();
  res.redirect('/');
});
