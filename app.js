const express = require('express');
const app = express();
const flash = require('express-flash');
const session = require("express-session");
const bcrypt = require('bcrypt');
const passport = require('passport');
const mongoose = require('mongoose');
const LocalStrategy = require('passport-local').Strategy;
require('dotenv').config();

const sgMail = require('@sendgrid/mail');
sgMail.setApiKey(process.env.SENDGRID_API_KEY);



const crypto = require('crypto');


const User = require('./models/User');

app.set('view-engine', 'ejs')
app.use(express.urlencoded({ extended: true }))

//database connection

mongoose.connect("mongodb://localhost/authentication-with-email-confirmation", { useNewUrlParser: true });
mongoose.set('useFindAndModify', false);


//authentication middleware setup 

app.use(session({
    secret: "cats",
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());






//authentication
passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});

passport.use(new LocalStrategy(
    async function (username, password, done) {


        const user = await User.findOne({ username: username });
        if (user === null) {
            return done(null, false, { message: 'No user found with that username' })
        }
        try {
            if (await bcrypt.compare(password, user.password)) {
                return done(null, user);
            } else {
                return done(null, false, { message: 'incorrect password' });
            }


        } catch (error) {
            console.log(error)
        }

    }
));






app.get('/', (req, res) => {
    res.render('index.ejs')
})

app.get('/login', (req, res) => {
    res.render('login.ejs')
})

app.post('/login',isVerified, passport.authenticate('local', {
    successRedirect: '/secret',
    failureRedirect: '/login',
    failureFlash: true
}));


app.get('/register', (req, res) => {
    res.render('register.ejs')
})

app.post('/register', async (req, res) => {
    try {
        const newUser = await User.create({
            username: req.body.username,
            email: req.body.email,
            emailToken: crypto.randomBytes(64).toString('hex'),
            isVerified: false,
            password: req.body.password,
            passwordConfirm: req.body.passwordConfirm
        });
        res.redirect('/login')

        const msg = {
            from: 'frozendawn@abv.bg',
            to: newUser.email,
            subject: 'email verification',
            text: `text msg ${newUser.emailToken}
            `,
            html: `
            html msg
            <a href="http://localhost:3000/verify-email?token=${newUser.emailToken}">Verify your account</a>
            <p>${newUser.emailToken}</p>`
        }
        await sgMail.send(msg)


    } catch (err) {
        console.log(err)
        res.redirect('/register')
    }
});

app.get('/verify-email', async (req, res, next) => {
    try {
        const user = await User.findOne({ emailToken: req.query.token })
        if (!user) {
            req.flash('error', 'Token is invalid')
            return res.redirect('/')
        }
        user.emailToken = null;
        user.isVerified = true;
        await user.save();
        await req.login(user, async (err) => {
            if (err) {
                return next(err);
            }
            
            req.flash('success', `Welcome ${user.username}`)
            res.redirect('/');
        })
    }
    catch (error) {
        console.log(error);
        req.flash('error', 'something went wrong in the verify email route')
        res.redirect('/')
    }
})

//authentication middleware
function isLoggedIn(req,res,next) {
    if(req.isAuthenticated()){
        return next();
    }else {
        res.redirect('/login')
    } 
   
}

async function isVerified(req,res,next) {
    try {
        const user = await User.findOne({ username: req.body.username});
        if (user.isVerified){
            return next();
        }
        req.flash('error', 'Your account has not been verified, please check your email')
        return res.redirect('/')
    } catch (error) {
        console.log(error)
    }
   
}

app.get('/secret',isLoggedIn, (req, res) => {
    res.render('secret.ejs')
})

app.listen(3000);