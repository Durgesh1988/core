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


var mongoose = require('mongoose');
var ObjectId = require('mongoose').Types.ObjectId;
var logger = require('_pr/logger')(module);

var Schema = mongoose.Schema;
var LogSchema = new Schema({
    actionId:{
        type: String,
        trim: true,
        required: true
    },
    sourceId:{
        type: String,
        trim: true,
        required: false
    },
    referenceId: {
        type: String,
        trim: true,
        required: false
    },
    err: {
        type: Boolean,
        default: false,
        required: true
    },
    log: {
        type: String,
        trim: true,
        required: false
    },
    timestamp: {
        type: Number,
        default: Date.now(),
        required: false
    }
});
var Logs = mongoose.model('logs', LogSchema);
var LogsDao = function() {
    this.insertLog = function(logData, callback) {
        var log = new Logs(logData);
        log.save(function(err, data) {
            if (err) {
                logger.error("Failed to insertLog", err);
                if (typeof callback === 'function') {
                    callback(err, null);
                }
                return;
            }
            if (typeof callback === 'function') {
                callback(null, data);
            }
        });
    };
    this.getLogsByReferenceId = function(referenceId, timestamp, callback) {
        logger.debug("Enter getLogsByReferenceId ", referenceId, timestamp);
        var queryObj = {
            referenceId: {
                $in: [referenceId]
            }
        }
        if (timestamp) {

            queryObj.timestamp = {
                "$gt": timestamp
            };
        }
        Logs.find(queryObj, function(err, data) {
            if (err) {
                logger.debug("Failed to getLogsByReferenceId ", referenceId, timestamp, err);
                callback(err, null);
                return;
            }
            logger.debug("Exit getLogsByReferenceId ", referenceId, timestamp);
            callback(null, data);
        });
    }

    this.getLogsByReferenceIdAndTimestamp = function(referenceId, timestampStarted, timestampEnded, callback) {
        var queryObj = {
            referenceId: {
                $in: [referenceId]
            }
        }
        if (timestampStarted) {
            queryObj.timestamp = {
                "$gt": timestampStarted
            };
            if (timestampEnded) {
                queryObj.timestamp.$lte = timestampEnded
            }
        }
        Logs.find(queryObj, function(err, data) {
            if (err) {
                callback(err, null);
                return;
            }
            callback(null, data);
        });
    }
    this.getLogsByActionId = function(actionId, callback) {
        logger.debug("Enter getLogsByActionId ", actionId);
        var queryObj = {
            actionId: actionId
        }
        Logs.find(queryObj, function(err, data) {
            if (err) {
                callback(err, null);
                return;
            }
            callback(null, data);
            return;
        });
    }

    this.getLogsBySourceId = function(sourceId, callback) {
        logger.debug("Enter getLogsBySourceId ", sourceId);
        var queryObj = {
            sourceId:sourceId
        }
        Logs.find(queryObj, function(err, data) {
            if (err) {
                callback(err, null);
                return;
            }
            callback(null, data);
            return;
        });
    }
}
module.exports = new LogsDao();
