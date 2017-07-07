
var winston = require('winston');
var path = require('path');
var mkdirp = require('mkdirp');
var util = require('util');
var events = require('events');
var log_folder = path.normalize(__dirname+"/../logs");
mkdirp.sync(log_folder);

winston.emitErrs = true;
var CatLogger = function(logger, calling_module){
    var exports = {};
    var methods = ["info", "debug", "warn", "error", "log"];

    events.EventEmitter.call(this);
    function change_args(args){
        var label = '';
        if(calling_module && calling_module.filename){
            label = "[" + path.basename(calling_module.filename) + "] ";
            args[0]=label+args[0];
        }
        return args;
    }
    methods.forEach(function(method){
        exports[method] = function(msg){
            var args = change_args(arguments);
            logger[method].apply(logger, args);
        };
    });
    return exports;
};

util.inherits(CatLogger,events.EventEmitter);
CatLogger.prototype.emitlog = function(data){
    this.emit("log",data);
}
var logger = new winston.Logger({
    transports: [
        new winston.transports.DailyRotateFile({
            level: 'debug',
            datePattern: '.yyyy-MM-dd',
            filename: 'schDashboard.log',
            dirname:log_folder,
            handleExceptions: true,
            json: true,
            maxsize: 5242880, //5MB
            maxFiles: 5,
            colorize: true,
            timestamp:true,
            name:'cat-file-log'
        }),
        new winston.transports.Console({
            level: 'debug',
            handleExceptions: true,
            json: false,
            colorize: true,
            name:'cat-console'
        })
    ],
    exitOnError: false
});

var express_logger = new winston.Logger({
    transports: [
        new winston.transports.DailyRotateFile({
            level: 'debug',
            datePattern: '.yyyy-MM-dd',
            filename: 'access.log',
            dirname:log_folder,
            handleExceptions: true,
            json: true,
            maxsize: 5242880, //5MB
            maxFiles: 5,
            colorize: true,
            timestamp:true,
            name:'express-file-log'
        })
    ],
    exitOnError: false
});

function create_logger(calling_module){
    return new CatLogger(logger, calling_module);
};
function create_express_logger(){
    return new CatLogger(express_logger);
};

module.exports = create_logger;
module.exports.ExpressLogger = create_express_logger;