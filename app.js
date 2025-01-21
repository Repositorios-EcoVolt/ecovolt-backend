var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var logger = require('morgan');

var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');
var membersRouter = require('./routes/members');
var informationRouter = require('./routes/information');

// Database
const useDatabase = require('./database');
useDatabase().catch((err) => console.error(err));

// Web Socket
const { Server } = require('socket.io');
const io = new Server(8080);

io.on('connection', (socket) => {
  // Log when a client connects to the server
  socket.on('connect', (client) => {
    // console.log('Socket ID: ', socket);
    console.log('Client ID: ', client);
  });

  // Receive a message from the client
  socket.on('send_telemetry', (msg) => {
    // Log the message
    console.log('Message received: ' + msg.toString());

    // Send the message to all clients (including the sender, broadcast)
    io.emit('send_telemetry', msg);
  });

  // Log when a client disconnects from the server
  socket.on('disconnect', (client) => {
    console.log('Client disconnected');
  });
});


var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(bodyParser.raw({ type: 'image/*', limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.use('/', indexRouter);
app.use('/users', usersRouter);
app.use('/information', informationRouter);
app.use('/information/member', membersRouter);

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
