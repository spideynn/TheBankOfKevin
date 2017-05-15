var async = require('async');
var crypto = require('crypto');
var nodemailer = require('nodemailer');
var passport = require('passport');
var User = require('../models/User');

/**
 * Login required middleware
 */
exports.ensureAuthenticated = function(req, res, next) {
  if (req.isAuthenticated()) {
    next();
  } else {
    res.redirect('/login');
  }
};

exports.ensureAdmin = function(req, res, next) {
  if (req.isAuthenticated()) {
    if (req.user.admin)   {
        next();
    } else {
        req.flash("error", {msg: "You are not allowed to access that resource."})
        res.redirect('/');
    }
  } else {
    res.redirect('/login');
  }
};

/**
 * GET /login
 */
exports.loginGet = function(req, res) {
  if (req.user) {
    return res.redirect('/');
  }
  res.render('account/login', {
    title: 'Log in'
  });
};

/**
 * POST /login
 */
exports.loginPost = function(req, res, next) {
  req.assert('email', 'Email is not valid').isEmail();
  req.assert('email', 'Email cannot be blank').notEmpty();
  req.assert('password', 'Password cannot be blank').notEmpty();
  req.sanitize('email').normalizeEmail({ remove_dots: false });

  var errors = req.validationErrors();

  if (errors) {
    req.flash('error', errors);
    return res.redirect('/login');
  }

  passport.authenticate('local', function(err, user, info) {
    if (!user) {
      req.flash('error', info);
      return res.redirect('/login')
    }
    req.logIn(user, function(err) {
      res.redirect('/');
    });
  })(req, res, next);
};

/**
 * GET /logout
 */
exports.logout = function(req, res) {
  req.logout();
  res.redirect('/');
};

/**
 * GET /signup
 */
exports.signupGet = function(req, res) {
  if (req.user) {
    return res.redirect('/');
  }
  res.render('account/signup', {
    title: 'Sign up'
  });
};

/**
 * POST /signup
 */
exports.signupPost = function(req, res, next) {
  req.assert('name', 'Name cannot be blank').notEmpty();
  req.assert('email', 'Email is not valid').isEmail();
  req.assert('email', 'Email cannot be blank').notEmpty();
  req.assert('password', 'Password must be at least 4 characters long').len(4);
  req.sanitize('email').normalizeEmail({ remove_dots: false });

  var errors = req.validationErrors();
  var admin = false;

  if (errors) {
    req.flash('error', errors);
    return res.redirect('/signup');
  }

  User.find({}, function (err, results) {
    if (!results.length) {
      admin = true;
    }
  });

  User.findOne({ email: req.body.email }, function(err, user) {
    if (user) {
      req.flash('error', { msg: 'The email address you have entered is already associated with another account.' });
      return res.redirect('/signup');
    }
    user = new User({
      name: req.body.name,
      email: req.body.email,
      password: req.body.password,
      shopDollars: 0,
      admin: admin,
      requests: []
    });
    user.save(function(err) {
      req.logIn(user, function(err) {
        res.redirect('/');
      });
    });
  });
};

/**
 * GET /account
 */
exports.accountGet = function(req, res) {
  res.render('account/profile', {
    title: 'My Account'
  });
};

/**
 * GET /account/admin
 */
exports.adminGet = function(req, res) {
    User.find({}, function (err, users) {
        var total = 0;
        users.forEach(function(user) {
            total += parseInt(user.shopDollars);
        })
        res.render('account/admin', {
            title: 'Admin Panel',
            users: users,
            totalShopDollars: total
        });
    });
};

/**
 * GET /account/:id/request/:request/approve
 */
exports.approveRequestGet = function(req, res) {
    var amount;
    User.findById(req.user.id, function(err, user) {
      var request = user.requests.id(req.params.request);
      request.read = true;
      request.approved = true;
      request.save();
      amount = request.amount;
      user.shopDollars -= amount;
      user.save(function(err) {
        req.flash('success', { msg: 'Approved the request and updated the user\'s balance.' });
        res.redirect('/account/admin');
      });
    });
};

/**
 * GET /account/:id/request/:request/deny
 */
exports.denyRequestGet = function(req, res) {
    User.findById(req.user.id, function(err, user) {
      var request = user.requests.id(req.params.request);
      request.read = true;
      request.approved = false;
      request.save();
      user.save(function(err) {
        req.flash('success', { msg: 'Denied the request.' });
        res.redirect('/account/admin');
      });
    });
};

/**
 * GET /account/:id/balance/:amount
 */
exports.setBalanceGet = function(req, res) {
    User.findById(req.params.id, function(err, user) {
      user.shopDollars = req.params.amount;
      user.save(function(err) {
        req.flash('success', { msg: 'Updated the user\'s balance.' });
        res.redirect('/account/admin');
      });
    });
};

/**
 * GET /account/:id/requests/allow
 */
exports.allowRequestGet = function(req, res) {
    User.findById(req.params.id, function(err, user) {
      user.canMakeWithdrawalRequests = true;
      user.save(function(err) {
        req.flash('success', { msg: 'The user can now make withdrawal requests.' });
        res.redirect('/account/admin');
      });
    });
};

/**
 * GET /account/:id/requests/deny
 */
exports.denyRequestGet = function(req, res) {
    User.findById(req.params.id, function(err, user) {
      user.canMakeWithdrawalRequests = false;
      user.save(function(err) {
        req.flash('success', { msg: 'The user can no longer make withdrawal requests.' });
        res.redirect('/account/admin');
      });
    });
};

/**
 * GET /account/request
 */
exports.requestGet = function(req, res) {
    res.render('account/request', {
        title: 'Request Money'
    });
};

/**
 * PUT /account/request
 * Send a request for shop dollars
 */
exports.requestPut = function(req, res, next) {
  req.assert('amount', 'Amount must be a number.').isInt();
  req.assert('amount', 'Amount cannot be blank.').notEmpty();

  var errors = req.validationErrors();

  if (errors) {
    req.flash('error', errors);
    return res.redirect('/account/request');
  }

  if (!req.user.canMakeWithdrawalRequests) {
    req.flash('error', { msg: 'You are not allowed to make withdrawal requests.' });
    res.redirect('/');
    return;
  }

  User.findById(req.user.id, function(err, user) {
    user.requests.push({
      date: Date.now(),
      amount:req.body.amount,
      read: false,
      approved: false,
      denyReason: undefined
    });
    user.save(function(err) {
      req.flash('success', { msg: 'Your request has been received.' });
      res.redirect('/');
    });
  });
};

/**
 * PUT /account
 * Update profile information OR change password.
 */
exports.accountPut = function(req, res, next) {
  if ('password' in req.body) {
    req.assert('password', 'Password must be at least 4 characters long').len(4);
    req.assert('confirm', 'Passwords must match').equals(req.body.password);
  } else {
    req.assert('email', 'Email is not valid').isEmail();
    req.assert('email', 'Email cannot be blank').notEmpty();
    req.sanitize('email').normalizeEmail({ remove_dots: false });
  }

  var errors = req.validationErrors();

  if (errors) {
    req.flash('error', errors);
    return res.redirect('/account');
  }

  User.findById(req.user.id, function(err, user) {
    if ('password' in req.body) {
      user.password = req.body.password;
    } else {
      user.email = req.body.email;
      user.name = req.body.name;
    }
    user.save(function(err) {
      if ('password' in req.body) {
        req.flash('success', { msg: 'Your password has been changed.' });
      } else if (err && err.code === 11000) {
        req.flash('error', { msg: 'The email address you have entered is already associated with another account.' });
      } else {
        req.flash('success', { msg: 'Your profile information has been updated.' });
      }
      res.redirect('/account');
    });
  });
};

/**
 * DELETE /account
 */
exports.accountDelete = function(req, res, next) {
  User.remove({ _id: req.user.id }, function(err) {
    req.logout();
    req.flash('info', { msg: 'Your account has been permanently deleted.' });
    res.redirect('/');
  });
};

/**
 * GET /forgot
 */
exports.forgotGet = function(req, res) {
  if (req.isAuthenticated()) {
    return res.redirect('/');
  }
  res.render('account/forgot', {
    title: 'Forgot Password'
  });
};

/**
 * POST /forgot
 */
exports.forgotPost = function(req, res, next) {
  req.assert('email', 'Email is not valid').isEmail();
  req.assert('email', 'Email cannot be blank').notEmpty();
  req.sanitize('email').normalizeEmail({ remove_dots: false });

  var errors = req.validationErrors();

  if (errors) {
    req.flash('error', errors);
    return res.redirect('/forgot');
  }

  async.waterfall([
    function(done) {
      crypto.randomBytes(16, function(err, buf) {
        var token = buf.toString('hex');
        done(err, token);
      });
    },
    function(token, done) {
      User.findOne({ email: req.body.email }, function(err, user) {
        if (!user) {
          req.flash('error', { msg: 'The email address ' + req.body.email + ' is not associated with any account.' });
          return res.redirect('/forgot');
        }
        user.passwordResetToken = token;
        user.passwordResetExpires = Date.now() + 3600000; // expire in 1 hour
        user.save(function(err) {
          done(err, token, user);
        });
      });
  }, // TODO: email provider setup
    function(token, user, done) {
      var transporter = nodemailer.createTransport({
        service: 'Mailgun',
        auth: {
          user: process.env.MAILGUN_USERNAME,
          pass: process.env.MAILGUN_PASSWORD
        }
      });
      var mailOptions = {
        to: user.email,
        from: 'support@yourdomain.com',
        subject: '✔ Reset your password on The Bank of Kevin',
        text: 'You are receiving this email because you (or someone else) have requested the reset of the password for your account.\n\n' +
        'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
        'http://' + req.headers.host + '/reset/' + token + '\n\n' +
        'If you did not request this, please ignore this email and your password will remain unchanged. This link will expire in one hour.\n'
      };
      transporter.sendMail(mailOptions, function(err) {
        req.flash('info', { msg: 'An email has been sent to ' + user.email + ' with further instructions.' });
        res.redirect('/forgot');
      });
    }
  ]);
};

/**
 * GET /reset
 */
exports.resetGet = function(req, res) {
  if (req.isAuthenticated()) {
    return res.redirect('/');
  }
  User.findOne({ passwordResetToken: req.params.token })
    .where('passwordResetExpires').gt(Date.now())
    .exec(function(err, user) {
      if (!user) {
        req.flash('error', { msg: 'Password reset token is invalid or has expired.' });
        return res.redirect('/forgot');
      }
      res.render('account/reset', {
        title: 'Password Reset'
      });
    });
};

/**
 * POST /reset
 */
exports.resetPost = function(req, res, next) {
  req.assert('password', 'Password must be at least 4 characters long').len(4);
  req.assert('confirm', 'Passwords must match').equals(req.body.password);

  var errors = req.validationErrors();

  if (errors) {
    req.flash('error', errors);
    return res.redirect('back');
  }

  async.waterfall([
    function(done) {
      User.findOne({ passwordResetToken: req.params.token })
        .where('passwordResetExpires').gt(Date.now())
        .exec(function(err, user) {
          if (!user) {
            req.flash('error', { msg: 'Password reset token is invalid or has expired.' });
            return res.redirect('back');
          }
          user.password = req.body.password;
          user.passwordResetToken = undefined;
          user.passwordResetExpires = undefined;
          user.save(function(err) {
            req.logIn(user, function(err) {
              done(err, user);
            });
          });
        });
    },
    function(user, done) {
      var transporter = nodemailer.createTransport({
        service: 'Mailgun',
        auth: {
          user: process.env.MAILGUN_USERNAME,
          pass: process.env.MAILGUN_PASSWORD
        }
      });
      var mailOptions = {
        from: 'support@yourdomain.com',
        to: user.email,
        subject: 'Your account password for The Bank of Kevin has been changed',
        text: 'Hello,\n\n' +
        'This is a confirmation that the password for your account ' + user.email + ' has just been changed. If this wasn\'t you, please contact support immediately.\n'
      };
      transporter.sendMail(mailOptions, function(err) {
        req.flash('success', { msg: 'Your password has been changed successfully.' });
        res.redirect('/account');
      });
    }
  ]);
};
