var logger = require('_pr/logger')(module);
var mongoose = require('mongoose');
var extend = require('extend');

var defaults = {
    host: 'localhost',
    port: '27017',
    dbName: 'test'
};

module.exports = function(options, callback) {
    var def = extend({}, defaults);
    options = extend(def, options);
    logger.debug(options);
    logger.debug(defaults);
    var connectionString = 'mongodb://';

    connectionString += options.host;

    connectionString += ':' + options.port;

    connectionString += '/' + options.dbName;
    logger.debug(connectionString);

    var connectWithRetry = function() {
        return mongoose.connect(connectionString, function(err) {
            if (err) {
                console.error('Failed to connect to mongo on startup - retrying in 5 sec', err);
                setTimeout(connectWithRetry, 5000);
            }
        });
    };
    connectWithRetry();

    mongoose.connection.on('connected', function() {
        callback(null);
    });

};