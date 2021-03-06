var express = require('express');
var path = require('path');
var logger = require('morgan');
var compression = require('compression');
var methodOverride = require('method-override');
var session = require('express-session');
var flash = require('express-flash');
var bodyParser = require('body-parser');
var expressValidator = require('express-validator');
var dotenv = require('dotenv');
var nunjucks = require('nunjucks');
var mongoose = require('mongoose').set('debug', true);
var passport = require('passport');

// Load environment variables from .env file
dotenv.load();

// Controllers
var homeController = require('./controllers/home');
var userController = require('./controllers/user');
var contactController = require('./controllers/contact');

// Passport OAuth strategies
require('./config/passport');

var app = express();


mongoose.connect(process.env.MONGODB_URI);
mongoose.connection.on('error', function() {
  console.log('MongoDB Connection Error. Please make sure that MongoDB is running.');
  process.exit(1);
});
// view engine setup
nunjucks.configure('views', {
  autoescape: true,
  express: app,
  watch: true,
  noCache: true
});
app.set('view engine', 'html');
app.set('port', process.env.PORT || 3000);
app.use(compression());
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(expressValidator());
app.use(methodOverride('_method'));
app.use(session({ secret: process.env.SESSION_SECRET, resave: true, saveUninitialized: true }));
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());
app.use(function(req, res, next) {
  res.locals.user = req.user;
  next();
});
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', homeController.index);
app.get('/account/request', userController.ensureAuthenticated, userController.requestGet);
app.put('/account/request', userController.ensureAuthenticated, userController.requestPut);
app.get('/account/admin', userController.ensureAdmin, userController.adminGet);
app.get('/account/:id/request/:request/approve', userController.ensureAdmin, userController.approveRequestGet);
app.get('/account/:id/request/:request/deny', userController.ensureAdmin, userController.denyRequestGet);
app.get('/account/:id/balance/:amount', userController.ensureAdmin, userController.setBalanceGet);
app.get('/account/:id/requests/deny', userController.ensureAdmin, userController.denyRequestGet);
app.get('/account/:id/requests/allow', userController.ensureAdmin, userController.allowRequestGet);
app.get('/account', userController.ensureAuthenticated, userController.accountGet);
app.put('/account', userController.ensureAuthenticated, userController.accountPut);
app.delete('/account', userController.ensureAuthenticated, userController.accountDelete);
app.get('/signup', userController.signupGet);
app.post('/signup', userController.signupPost);
app.get('/login', userController.loginGet);
app.post('/login', userController.loginPost);
app.get('/forgot', userController.forgotGet);
app.post('/forgot', userController.forgotPost);
app.get('/reset/:token', userController.resetGet);
app.post('/reset/:token', userController.resetPost);
app.get('/logout', userController.logout);

// Production error handler
if (app.get('env') === 'production') {
  app.use(function(err, req, res, next) {
    console.error(err.stack);
    res.sendStatus(err.status || 500);
  });
}

app.listen(app.get('port'), function() {
  console.log('Express server listening on port ' + app.get('port'));
});

module.exports = app;
