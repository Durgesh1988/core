/*
 Copyright [2016] [Relevance Lab]

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */


//var logger = require('_pr/logger')(module);
var spawn = require('child_process').spawn;
var exec = require('child_process').exec;
var readline = require('readline');

var currentDirectory = __dirname;

function getDefaultsConfig() {
    var config = {
        express: {
            port: 3002,
            express_sid_key: 'express.sid',
            sessionSecret: 'sessionSekret'
        },
        jwt: {
            secret: "jwtSecr3t",
            expiresInSec: 604800
        },
        app_run_port: 3002,
        app_run_secure_port:443,
        tempDirName: 'temp',
        schHomeDirName: 'sch',
        constantData: {
            sort_order : "asc",
            sortReferanceData : {
                "incident":"createdOn"
            },
            skip_Records : 1,
            max_record_limit : 200,
            record_limit : 50
        },
        db: {
            dbName: 'sch',
            host: 'localhost',
            port: '27017'
        },
        authStrategy: {
            local: true,
            externals: false
        },
        logServerUrl: '',
        features: {
            appcard: false
        },
        get tempDir() {
            return this.schHomeDirName +"/" + this.tempDirName + "/";
        }
    };
    return config;
}

function parseArguments() {
    var cliArgs = require("command-line-args");
    var cli = cliArgs([{
        name: "help",
        alias: "h",
        type: Boolean,
        description: "Help"
    }, {
        name: "catalyst-port",
        type: String,
        description: "Catalyst port number"
    }, {
        name: "db-host",
        type: String,
        description: "DB Host"
    }, {
        name: "db-port",
        type: String,
        description: "DB Port"
    }, {
        name: "db-name",
        type: String,
        description: "DB Port"
    }]);

    var options = cli.parse();

    /* generate a usage guide */
    var usage = cli.getUsage({
        header: "catalyst help",
        footer: "For more information, visit http://www.relevancelab.com"
    });

    if (options.help) {
        console.log(usage);
        process.exit(0);
    }
    return options;
}

function getConfig(config, options) {
    if (options['catalyst-port']) {
        var catalystPort = parseInt(options['catalyst-port']);
        if (catalystPort) {
            config.app_run_port = catalystPort;
            config.express.port = catalystPort;
        }
    }
    config.db.host = options['db-host'] ? options['db-host'] : config.db.host;
    config.db.port = options['db-port'] ? options['db-port'] : config.db.port;
    config.db.dbName = options['db-name'] ? options['db-name'] : config.db.dbName;
    return config;
}

function installPackageJson() {
    console.log("Installing node packages from pacakge.json");
    var procInstall = spawn('npm', ['install', '--unsafe-perm']);
    procInstall.stdout.on('data', function(data) {
        console.log("" + data);
    });
    procInstall.stderr.on('data', function(data) {
        console.error("" + data);
    });
    procInstall.on('close', function(pacakgeInstallRetCode) {
        if (pacakgeInstallRetCode === 0) {
            console.log("Installation Successfull.");
            process.exit(0);
        } else {
            console.log("Error occured while installing packages from apidoc.json");
            process.exit(1);
        }
    });
}

function createConfigFile(config) {
    console.log('creating configuration json file');
    var configJson = JSON.stringify(config);
    var fs = require('fs');
    fs.writeFileSync('app/config/catalyst-config.json', configJson);
}
console.log('Installing node packages required for installation');
proc = spawn('npm', ['install', "command-line-args@0.5.3", 'mkdirp@0.5.0', 'fs-extra@0.18.0', 'ldapjs@0.7.1', 'mongodb@2.2.29']);
proc.on('close', function(code) {
    if (code !== 0) {
        throw "Unable to install packages"
    } else {
        var options = parseArguments();
        var defaultConfig = getDefaultsConfig();
        var config = getConfig(defaultConfig, options);
        console.log('creating catalyst home directory');
        var fsExtra = require('fs-extra');
        var mkdirp = require('mkdirp');
        mkdirp.sync(config.tempDir);
        createConfigFile(config);
        installPackageJson();
    }
});
proc.stdout.on('data', function(data) {
    console.log("" + data);
});

proc.stderr.on('data', function(data) {
    console.error("" + data);
});
