/*
 Copyright [2016] [Relevance Lab]
 loLicensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */


var aws = require('aws-sdk');
var logger = require('_pr/logger')(module);
var fs = require('fs');

if (process.env.http_proxy) {
    aws.config.update({
        httpOptions: {
            proxy: process.env.http_proxy
        }
    });
}

var S3 = function(awsSettings) {

    var that = this;
    var params = new Object();

    if (typeof awsSettings.region !== undefined) {
        params.region = awsSettings.region;
    }
    if (typeof awsSettings.accessKey !== undefined && typeof awsSettings.secretKey !== undefined) {
        params.accessKeyId = awsSettings.accessKey;
        params.secretAccessKey = awsSettings.secretKey;
    }

    var s3 = new aws.S3(params);

    this.getObject = function(params,key, callback) {
        if(key==='time') {
            s3.getObject(params, function (err, data) {
                if (err) {
                    logger.debug("Got getObject info with error: ", err);
                    callback(err, null);
                    return;
                }
                callback(null, data.LastModified);
            });
        }else if(key === 'file'){
            var file = fs.createWriteStream('rlBilling.zip');
            var fileStream = s3.getObject(params).createReadStream();
            fileStream.pipe(file);
            file.on('finish',function(){
                console.log('done');
                callback(null,true);
            });
        }

    };


}

module.exports = S3;