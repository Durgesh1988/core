var mkdirp = require('mkdirp');
var fs = require('fs');
var currentDirectory = __dirname;
var path = require('path');
var logger = require('_pr/logger')(module);


var configJson;
try {
    configJson = fs.readFileSync(currentDirectory + '/catalyst-config.json', {
        'encoding': 'utf8'
    });
} catch (err) {
    logger.error(err);
    configJson = null;
    throw err;
}

if (configJson) {
    var config = JSON.parse(configJson);
}


//creating path

mkdirp.sync(config.tempDir);
module.exports = config;