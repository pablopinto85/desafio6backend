const express = require('express');
const passport = require('passport');
const GitHubStrategy = require('passport-github').Strategy;
const session = require('express-session');
const flash = require('connect-flash');
const mongoose = require('mongoose');
const UserModel = require('./models/user');
const MongoStore = require(`connect-mongo`);
const LocalStrategy = require('passport-local').Strategy;
const crypto = require('crypto');
const { isValidPassword } = require('./utils'); 



mongoose.connect('mongodb+srv://pablopinto1985:pablo1985@ecommerce.kyhfmlv.mongodb.net/?retryWrites=true&w=majority');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

optionsMongo = { useNewUrlParser: true, useUnifiedTopology: true };
app.use(session({
    store: MongoStore.create({
        mongoUrl: 'mongodb+srv://pablopinto1985:pablo1985@ecommerce.kyhfmlv.mongodb.net/?retryWrites=true&w=majority',
        mongoOptions: optionsMongo,
        ttl: 10
    }),
    secret: '123456',
    resave: true,
    saveUninitialized: true
}));


app.use(session({
    secret: '1234',
    resave: true,
    saveUninitialized: true
}));


passport.use(new GitHubStrategy({
    clientID: 'Iv1.edfa107f63171b66',
    clientSecret: 'dd0d073d606f562db9bd06b8a400dc5f8315edbf',
    callbackURL: 'http://localhost:8080/api/sessions/githubcallback'
},
async (accessToken, refreshToken, profile, done) => {
    
    const existingUser = await UserModel.findOne({ githubId: profile.id });

    if (existingUser) {
        return done(null, existingUser);
    }

   
    const newUser = new UserModel({
        githubId: profile.id,
        username: profile.username 
    });
    await newUser.save();

    return done(null, newUser);
}));


passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    const user = await UserModel.findById(id);
    done(null, user);
});



app.use(flash());
app.set('view engine', 'ejs');

app.use(passport.initialize());
app.use(passport.session());


const strategyLogin = new LocalStrategy(async (username, password, callbackDone) => {
    try {
        const user = await UserModel.findOne({ username });
        if (!user) {
            return callbackDone(null, false, { message: `Nombre de usuario incorrecto` });
        }
        if (!isValidPassword(user.password, password)) {
            return callbackDone(null, false, { message: `Contraseña incorrecta` });
        }
        return callbackDone(null, user);
    }
    catch (err) {
        callbackDone(err);
    }
});




function createHash(password) {
    const salt = crypto.randomBytes(16).toString('hex'); 
    const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
    return hash; 
}


const strategySignup = new LocalStrategy({
    
    passReqToCallback: true
}, async (req, username, password, callbackDone) => {
    try {
        const user = await UserModel.findOne({ username });
        if (user) {
            return callbackDone(null, false, { message: `El nombre de usuario ya existe` });
        }

        const newUser = new UserModel();
        newUser.username = username;
        const hashedPassword = createHash(req.body.password);
        newUser.password = hashedPassword.hash;
        newUser.salt = hashedPassword.salt;
        newUser.password = createHash(password); 
        newUser.email = req.body.email;

        const userSave = await newUser.save();

        return callbackDone(null, userSave);
    }
    catch (err) {
        callbackDone(err);
    }
});

passport.use('login', strategyLogin);
passport.use('signup', strategySignup);

passport.serializeUser((user, callbackDone) => {
    console.log(`serializeUser`);
    callbackDone(null, user._id);
});

passport.deserializeUser(async (id, callbackDone) => {
    console.log(`deserializeUser`);
    try {
        const user = await UserModel.findById(id);
        callbackDone(null, user);
    } catch (err) {
        callbackDone(err);
    }
});


app.get('/login', (req, res) => {
    return res.render('login', { message: req.flash('error') }); 
});

app.get('/auth/github', passport.authenticate('github'));
app.get('/auth/github/callback', passport.authenticate('github', {
    successRedirect: '/welcome',
    failureRedirect: '/login', 
    failureFlash: true 
}));

app.post('/login', passport.authenticate('login', { 
    successRedirect: '/welcome', 
    failureRedirect: '/loginerror', 
    failureFlash: true  
}));

app.get('/signup', (req, res) => {
    return res.render('signup', { message: req.flash('error') }) 
});

app.post('/signup', passport.authenticate('signup', {
    successRedirect: '/welcome', 
    failureRedirect: '/signuperror', 
    failureFlash: true 
}));

app.get('/loginerror', (req, res) => {
    return res.render('login', { message: req.flash('error') });
});

app.get('/api/sessions/githubcallback', passport.authenticate('github', {
    successRedirect: '/welcome', 
    failureRedirect: '/login', 
    failureFlash: true 
}));

app.get('/welcome', (req, res) => {
    if (req.isAuthenticated()) {
        const user = req.user;
        const message = 'Bienvenido, ' + user.username;
        return res.render('welcome', { message: message });
    }
    return res.redirect('/login'); 
});

app.get('/', (req, res) => {
    if (req.isAuthenticated()) {
        const user = req.user;
        const message = 'Bienvenido, ' + user.username ;
        return res.render('welcome', { message: message });
    }
    return res.render('login', { message: null });
});

const PORT = 8080;

app.listen(PORT, () => console.log(`Servidor escuchando en el puerto ${PORT}`));

