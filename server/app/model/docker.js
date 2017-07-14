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


var fileIo = require('_pr/lib/utils/fileio');
var SSH = require('_pr/lib/utils/sshexec');
var resourceModel = require('_pr/model/resources/resources');
var credentialCrp = require('_pr/lib/credentialcryptography.js');
var logger = require('_pr/logger')(module);

var Docker = function() {
    this.runDockerCommands = function(cmd, resourceId, callback, callbackOnStdOut, callbackOnStdErr) {
        resourceModel.getResourceById(resourceId, function(err, data) {
            if (err) {
                callback(err,null);
                return;
            }
            if (data.length) {
                logger.debug('reached docker cmd');
                var instanceOptions = data[0];
                credentialCrp.decryptCredential(instanceOptions.credentials, function(err, decryptedCredentials) {
                    if (err) {
                        callback(err);
                        return;
                    }
                    var options = {
                        host: instanceOptions.resourceDetails.publicIp,
                        port: '22',
                        username: decryptedCredentials.username, //'ec2-user',
                        privateKey: decryptedCredentials.pemFileData, //'/development/catalyst/D4DFE/D4D/config/catalyst.pem'
                        password: decryptedCredentials.password
                    };
                    var sshParamObj = {
                        host: options.host,
                        port: options.port,
                        username: options.username
                    };
                    if (options.privateKey) {
                        sshParamObj.privateKey = options.privateKey;
                        if (options.passphrase) {
                            sshParamObj.passphrase = options.passphrase;
                        }
                    } else {
                        sshParamObj.password = options.password;
                    }
                    var sshConnection = new SSH(sshParamObj);
                    sshConnection.exec(cmd, function(err, code) {
                        if (decryptedCredentials.pemFileLocation) {
                            fileIo.removeFile(decryptedCredentials.pemFileLocation, function() {
                                logger.debug('temp file deleted');
                            });
                        }
                        callback(err, code);
                    }, callbackOnStdOut, callbackOnStdErr);
                });
            }
        });
    }

    this.checkDockerStatus = function(resourceId, callback, callbackOnStdOut, callbackOnStdErr) {
        logger.debug(resourceId);
        var cmd = "sudo docker ps";
        resourceModel.getResourceById(resourceId, function(err, data) {
            if (err) {
                callback(err,null);
                return;
            }
            if (data.length) {
                logger.debug('reached docker cmd');
                var instanceOptions = data[0];
                credentialCrp.decryptCredential(instanceOptions.credentials, function(err, decryptedCredentials) {
                    if (err) {
                        callback(err);
                        return;
                    }
                    var options = {
                        host: instanceOptions.resourceDetails.publicIp,
                        port: '22',
                        username: decryptedCredentials.username,
                        privateKey: decryptedCredentials.pemFileData,
                        password: decryptedCredentials.password
                    };

                    var sshParamObj = {
                        host: options.host,
                        port: options.port,
                        username: options.username
                    };
                    if (options.privateKey) {
                        sshParamObj.privateKey = options.privateKey;
                        if (options.passphrase) {
                            sshParamObj.passphrase = options.passphrase;
                        }
                    } else {
                        sshParamObj.password = options.password;
                    }
                    var sshConnection = new SSH(sshParamObj);
                    sshConnection.exec(cmd, function(err, code) {
                        if (decryptedCredentials.pemFileLocation) {
                            fileIo.removeFile(decryptedCredentials.pemFileLocation, function() {
                                logger.debug('temp file deleted');
                            });
                        }
                        callback(err, code);
                    }, callbackOnStdOut, callbackOnStdErr);
                });
            }
        });
    }
}

module.exports = Docker;
