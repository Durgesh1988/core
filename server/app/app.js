
var express = require("express");
var app = express();
var path = require("path");
var http = require("http");
var https = require("https");
var fs = require('fs');
var logger = require('_pr/logger')(module);
var passport = require('passport');
var expressCompression = require('compression');
var expressCookieParser = require('cookie-parser');
var expressSession = require('express-session');
var expressBodyParser = require('body-parser');
var multipart = require('connect-multiparty');
var expressMultipartMiddleware = multipart();
var appConfig = require('_pr/config');
var mongoose = require('mongoose');
var MongoStore = require('connect-mongo')(expressSession);
var mongoDbConnect = require('_pr/lib/mongodb');
var mongoose = require('mongoose');
logger.debug('Starting Catalyst');
logger.debug('Logger Initialized');
var dboptions = {
    host: process.env.DB_HOST || appConfig.db.host,
    port: appConfig.db.port,
    dbName: appConfig.db.dbName
};
mongoDbConnect(dboptions, function(err) {
    if (err) {
        logger.error("Unable to connect to mongo db >>" + err);
        throw new Error(err);
    } else {
        logger.debug('connected to mongodb - host = %s, port = %s, database = %s', dboptions.host, dboptions.port, dboptions.dbName);
    }
});
var mongoStore = new MongoStore({
    mongooseConnection: mongoose.connection
}, function() {

});

app.set('port', process.env.PORT || appConfig.app_run_port);
app.set('sport', appConfig.app_run_secure_port);
app.use(expressCompression());
app.use(expressCookieParser());

logger.debug("Initializing Session store in mongo");

var sessionMiddleware = expressSession({
    secret: 'sessionSekret',
    store: mongoStore,
    resave: false,
    saveUninitialized: true
});
app.use(sessionMiddleware);


app.use(expressMultipartMiddleware);

// parse application/x-www-form-urlencoded
app.use(expressBodyParser.urlencoded({
    limit: '50mb',
    extended: true
}))

// parse application/json


app.use(expressBodyParser.json({
    limit: '50mb'
}))




//app.use(app.router);

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";



var server = http.createServer(app);


app.all('*', function(req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "X-Requested-With");
    next();
});


logger.debug('Setting up application routes');
var routes = require('./routes/routes.js');
var routerV1 = express.Router();
routes.setRoutes(routerV1);

app.use(routerV1);
app.use('/api/v1.0', routerV1);


app.use(function(req, res, next) {
    if (req.accepts('json')) {
        var errorResponse = {
            'status': 404,
            'message': 'Not found'
        };
        res.send(errorResponse);
        return;
    }
});

server.listen(app.get('port'), function() {
    logger.debug('Express server listening on port ' + app.get('port'));
});