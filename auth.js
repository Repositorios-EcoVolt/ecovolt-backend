// Attempting to use JSON web tokens (JWT)
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');

const UserSchema = require('./models/user');

passport.use(
    new LocalStrategy({
        usernameField: 'username',
        passwordField: 'password'
    },
    async (username, password, done) => {
        try {
            const user = await UserSchema.findOne({ username: username});

            if (!user) {
                return done(null, false, { message: 'Invalid username or password.' });
            }

            const isMatch = await bcrypt.compare(password, user.password);

            if (!isMatch) {
                return done(null, false, { message: 'Invalid username or password.' });
            }

            return done(null, user);
        } catch (err) {
            return done(err);
        }
    })
);

// Serialization
passport.serializeUser((user, done) => done(null, user.id));

// Deserialization
passport.deserializeUser((id, done) => {
    try {
        const user = UserSchema.findById(id);
        return done(null, user);
    } catch (err) {
        return done(err);
    }
});

/*
const checkToken = (req, res, next) => {
    passport.authenticate('jwt', { session: false }, (err, user, info) => {
        if (err) {
            return next(err);
        }

        if (!user) {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        req.user = user;
        return next();
    })(req, res, next);
}
*/

module.exports = passport;