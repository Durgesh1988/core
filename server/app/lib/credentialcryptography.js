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


/*
This is a temproray class. these methods will me moved to model once mvc comes into pictured
*/
var Cryptography = require('./utils/cryptography');
var appConfig = require('_pr/config');
var uuid = require('node-uuid');
var fileUpload = require('_pr/model/file-upload/file-upload');
var fileIo = require('./utils/fileio');
var fs = require('fs');
var logger = require('_pr/logger')(module);

module.exports.encryptCredential = function(credentials, callback) {
    var cryptoConfig = appConfig.cryptoSettings;
    var encryptedCredentials = {};
    var cryptography = new Cryptography(cryptoConfig.algorithm, cryptoConfig.password);
    if (credentials) {
        encryptedCredentials.username = credentials.username?credentials.username:null;
        if (credentials.password) {
            encryptedCredentials.password = cryptography.encryptText(credentials.password, cryptoConfig.encryptionEncoding, cryptoConfig.decryptionEncoding);
            callback(null, encryptedCredentials);
        } else {
            var encryptedPemFileLocation = appConfig.instancePemFilesDir + uuid.v4();
            var fileId = uuid.v4();
            cryptography.encryptFile(credentials.pemFileData, cryptoConfig.encryptionEncoding, encryptedPemFileLocation, cryptoConfig.decryptionEncoding, function(err) {
                fileUpload.uploadFile(fileId,encryptedPemFileLocation,fileId,function(err,data){
                    fileIo.removeFile(encryptedPemFileLocation, function(err) {
                        if (err) {
                            logger.debug("Unable to delete temp pem file =>", err);
                        } else {
                            logger.debug("temp pem file deleted =>");
                        }
                    });
                    if (err) {
                        callback(err, null);
                        return;
                    }
                    encryptedCredentials.fileId = fileId;
                    callback(null, encryptedCredentials);
                })
            });
        }
    }
};

module.exports.decryptCredential = function(credentials, callback) {
    var decryptedCredentials = {};
    decryptedCredentials.username = credentials.username;
    var cryptoConfig = appConfig.cryptoSettings;
    var cryptography = new Cryptography(cryptoConfig.algorithm, cryptoConfig.password);
    if (credentials.fileId) {
        fileUpload.getReadStreamFileByFileId(credentials.fileId,function(err,fileDetails){
            if(err){
                callback(err,null);
            }else{
                decryptedCredentials.base64FileData = new Buffer(cryptography.decryptText(fileDetails.fileData, cryptoConfig.decryptionEncoding, cryptoConfig.encryptionEncoding)).toString('base64');
                decryptedCredentials.pemFileData = cryptography.decryptText(fileDetails.fileData, cryptoConfig.decryptionEncoding, cryptoConfig.encryptionEncoding);
                callback(null, decryptedCredentials);
            }
        })
    }else {
        decryptedCredentials.password = cryptography.decryptText(credentials.password, cryptoConfig.decryptionEncoding, cryptoConfig.encryptionEncoding);
        callback(null, decryptedCredentials);
    }
};