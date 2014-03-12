var passport = require('passport'),
    bcrypt = require('bcrypt'),
    FacebookStrategy = require('passport-facebook').Strategy,
    LocalStrategy = require('passport-local').Strategy;

function configure(db) {
    function findByOAuth(id, callback) {
        db.view('users/byOAuth', {
            key: id,
            include_docs: true
        }, function (err, body) {
            if (err) {
                console.error(err);
                console.trace(err.stack);
                return callback(err);
            }
            if (!body.rows.length) {
                return callback('not_found');
            }
            callback(null, body.rows[0].doc);
        });
    }

    function findByEmail(email, callback) {
        db.view('users/byEmail', {
            key: email,
            include_docs: true
        }, function (err, body) {
            if (err) {
                console.error(err);
                console.trace(err.stack);
                return callback('Can not fetch the user');
            }
            if (!body.rows.length) {
                return callback();
            }
            callback(null, body.rows[0].doc);
        });
    }

    function findById(id, callback) {
        db.get(id, function (err, user) {
            if (err) {
                callback(err);
            }
            callback(null, user);
        });
    }
    passport.serializeUser(function (user, done) {
        done(null, user._id);
    });
    passport.deserializeUser(function (id, done) {
        findById(id, function (err, user) {
            done(err, user);
        });
    });
    // Use the LocalStrategy within Passport.
    //   Strategies in passport require a `verify` function, which accept
    //   credentials (in this case, a username and password), and invoke a callback
    //   with a user object.  In the real world, this would query a database;
    //   however, in this example we are using a baked-in set of users.
    passport.use(new LocalStrategy({
        usernameField: 'email',
        passwordField: 'password'
    }, function (email, password, done) {
        // Find the user by username.  If there is no user with the given
        // username, or the password is not correct, set the user to `false` to
        // indicate failure and set a flash message.  Otherwise, return the
        // authenticated `user`.
        findByEmail(email, function (err, user) {
            if (err) {
                return done(err);
            }
            if (!user) {
                return done(null, false, {
                    message: email + ' does not belong to any user. Did you mistyped it?.'
                });
            }
            if (!bcrypt.compareSync(password, user.hashedPassword)) {
                return done(null, false, {
                    message: 'Password mismatch.'
                });
            }
            return done(null, user);
        });
    }));
    // Passport session setup.
    // To support persistent login sessions, Passport needs to be able to
    // serialize users into and deserialize users out of the session. Typically,
    // this will be as simple as storing the user ID when serializing, and finding
    // the user by ID when deserializing. However, since this example does not
    // have a database of user records, the complete GitHub profile is serialized
    // and deserialized.
    passport.use(new FacebookStrategy({
        clientID: process.env.FACEBOOK_APP_ID,
        clientSecret: process.env.FACEBOOK_APP_SECRET,
        //profileFields: ['id', 'name', 'photos', 'gender', 'photos', 'displayName', 'profileUrl', 'username', 'email'],
        callbackURL: 'http://lamodecampus.com:3000/auth/facebook/callback'
    }, function (accessToken, refreshToken, profile, done) {
        var newUser = {
            type: 'user',
            name: profile.name.givenName,
            surname: profile.name.familyName,
            oauth: [{
                id: profile.id,
                data: profile
            }],
	    email: profile.emails && profile.emails.length &&  profile.emails[0].value
        };
        findByOAuth(profile.id, function (err, user) {
            if (err === 'not_found') {
                return db.save(newUser, function (err, res) {
                    if (err) {
                        console.error(err);
                        console.trace(err.stack);
                        return done(err);
                    }
                    if (res.ok) {
                        newUser._id = res.id;
                        return done(null, newUser);
                    }
                });
            }
            if (err) {
                console.error(err);
                console.trace(err.stack);
                return done(err);
            }
            return done(null, user);
        });
    }));
}
exports.configure = configure;
