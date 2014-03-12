var express = require('express'),
    debug = require('debug')('login'),
    bcrypt = require('bcrypt'),
    bruteforce = require('connect-bruteforce'),
    Recaptcha = require('recaptcha').Recaptcha,
    passport = require('passport'),
    loginBruteForce = new bruteforce({
        banFactor: 500,
        banMax: 2000
    }),
    app = module.exports = express(),
    recaptchaKeys = {
        /*
         * Recaptcha keypair
         * http://www.google.com/recaptcha/whyrecaptcha
         */
        PUBLIC: process.env.RECAPTCHA_PUBLIC,
        PRIVATE: process.env.RECAPTCHA_PRIVATE
    };
app.set('views', __dirname);
app.set('view engine', 'jade');
app.use(function (req, res, next) {
    res.locals.recaptcha_form = req.session.recaptchaForm || '';
    delete req.session.recaptchaForm;
    return next();
});
/*app.on('mount', function () {
    app.db = app.parent.db;
});
*/
// !IMPORTANT
// We can not use the req.pushMessage because we can 
// not 302, otherwise recaptcha validation would be unsync

function pushMessage(res, type, foreword, text) {
    res.locals.messages = res.locals.messages || [];
    res.locals.messages.push({
        type: type,
        foreword: foreword,
        text: text
    });
}
//////////////////////////////////////////////////////////////////
// Recaptcha integration
//
// We require recaptcha validation after a *number* of
// bad logins.
//
//////////////////////////////////////////////////////////////////

function requireRecaptchaAfterTries(number) {
    return function (req, res, next) {
        var recaptcha, data, badAttempts = req.delayed && req.delayed.counter || -1;
        // Note: We show recaptcha form prior to require it
        if (badAttempts >= number) {
            res.locals.recaptcha_form = (new Recaptcha(recaptchaKeys.PUBLIC, recaptchaKeys.PRIVATE)).toHTML();
        }
        if ((req.requireRecaptcha = badAttempts > number)) {
            data = {
                remoteip: req.connection.remoteAddress,
                challenge: req.body.recaptcha_challenge_field,
                response: req.body.recaptcha_response_field
            };
            recaptcha = new Recaptcha(recaptchaKeys.PUBLIC, recaptchaKeys.PRIVATE, data);
            recaptcha.verify(function (success, error) {
                // Error here can be many things. I.e if the user did not 
                // provide captcha response
                req.isValidRecaptcha = {
                    success: success,
                    error: error
                };
                return next();
            });
        } else {
            return next();
        }
    };
}
app.get('/', function (req, res) {
    res.render('index', {
        user: req.user,
        title: 'Login'
    });
});
// POST /login
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  If authentication fails, the user will be redirected back to the
//   login page.  Otherwise, the primary route function function will be called,
//   which, in this example, will redirect the user to the home page.
//
//   curl -v -d "username=bob&password=secret" http://127.0.0.1:3000/login
app.post('/', loginBruteForce.prevent, requireRecaptchaAfterTries(3), function (req, res, next) {
    if (req.requireRecaptcha && !req.isValidRecaptcha.success) {
        pushMessage(res, 'danger', 'Error', 'Authentication failed. Bad captcha');
        loginBruteForce.ban(req);
        return next();
    }
    passport.authenticate('local', function (err, user, info) {
        if (err) {
            loginBruteForce.ban(req);
            pushMessage(res, 'danger', 'Error', err.message);
            return next();
        }
        if (!user) {
            pushMessage(res, 'danger', 'Error', info.message);
            loginBruteForce.ban(req);
            return next();
        }
        req.logIn(user, function (err) {
            if (err) {
                pushMessage(res, 'danger', 'Error', err.message);
                return next();
            }
            loginBruteForce.unban(req);
            delete req.session.recaptchaForm;
            res.redirect(302, '/');
        });
    })(req, res, next);
}, function (req, res) {
    res.render('index', {
        user: req.user,
        title: 'Login'
    });
});
