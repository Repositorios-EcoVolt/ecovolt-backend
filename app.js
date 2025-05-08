var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var logger = require('morgan');
const csrf = require('csurf');

var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');
var membersRouter = require('./routes/members');
var galleryRouter = require('./routes/gallery');
var donationsRouter = require('./routes/donations');
var informationRouter = require('./routes/information');

// Database
const useDatabase = require('./database');
useDatabase().catch((err) => console.error(err));

// CORS middleware
const cors = require('cors');
const corsOptions = {
  origin: '*.lemi-tec.mx',
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  optionsSuccessStatus: 200,
  
};

// CSRF middleware
const csrfOptions = {
  key: 'csrftoken',
  secure: true,
  httpOnly: true,
  sameSite: 'strict'
}

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
// app.use(csrf({ cookie: csrfOptions }));
app.use(cors(corsOptions, function(req, callback){
  callback(null, {origin: true});
}));
app.use(bodyParser.raw({ type: 'image/*', limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.use('/', indexRouter);
app.use('/users', usersRouter);
app.use('/donations', donationsRouter);
app.use('/information', informationRouter);
app.use('/information/member', membersRouter);
app.use('/information/gallery', galleryRouter);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
