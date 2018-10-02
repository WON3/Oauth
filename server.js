const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const massive = require('massive');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');

require('dotenv').config();

const app = express();

app.use(cors());
app.use(bodyParser.json());

massive(process.env.CONNECTION_STRING)
    .then((dbInstance => {
        app.set('db', dbInstance);
        console.log('Connected to db!')
    }))

app.use(session({
    secret: process.env.SESSION_SECRET,
  }))

app.use(passport.initialize());
app.use(passport.session());

let attempts = 0;

passport.use('login', new LocalStrategy({
    usernameField: 'email', 
    passReqToCallback: true,
}, (req, email, password, done) => {
    if(attempt >= 3){
        done('Sorry this account')
    }else{
        const db = req.app.get('db')
        db.user_table.findOne({ email: email })
            .then(user => {
                if (!user) {
                    bcrypt.hash(password, 10)
                    .then((password)=>{
                        return db.user_table.insert({email, password})
                    })
                    .then((user)=>{
                        delete user.password;
                        done(null, user);
                    })
                }else if(!bcrypt.compareSync(password, user.password)){
                    attempts++
    
                    return done('Invalid email or password');
                }else{
                    delete user.password;
                    done(null, user);
                }
            })
            .catch(err => {
                done(err);
            });
    }

}));

passport.serializeUser((user, done) => {
    if (!user) {
        done('No user');
    }

    done(null, user);
    },
);

passport.deserializeUser((user, done) => {
    done(null, user);
});


app.post('/login', passport.authenticate(['login']), (req, res, next)=>{
    res.send('Successful Login!')
})

app.get('/api/hello', (req, res) => {
    res.send(req.user)
})

const port =  process.env.PORT || 8002
app.listen(port, ()=>{
    console.log(`Listening on port ${port}`)
})