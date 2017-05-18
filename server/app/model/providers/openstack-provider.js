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

var logger = require('_pr/logger')(module);
var mongoose = require('mongoose');
var baseProvider = require('./base-providers.js');
var Schema = mongoose.Schema;
var ObjectId = require('mongoose').Types.ObjectId;
var providers = require('./providers.js');


var openStackProviderSchema = new baseProvider({
    providerDetails: {
        username: {
            type: String,
            required: true,
            trim: true
        },
        password: {
            type: String,
            required: true,
            trim: true
        },
        host: {
            type: String,
            required: true,
            trim: true
        },
        serviceEndPoints: {
            compute: {
                type: String,
                trim: true
            },
            network: {
                type: String,
                trim: true
            },
            image: {
                type: String,
                trim: true
            },
            ec2: {
                type: String,
                trim: true
            },
            identity: {
                type: String,
                trim: true
            }
        },
        tenantId: {
            type: String,
            required: true,
            trim: true
        },
        tenantName: {
            type: String,
            required: true,
            trim: true
        },
        keyName: {
            type: String,
            required: true,
            trim: true
        },
        projectName: {
            type: String,
            required: true,
            trim: true
        },
        pemFileId : {
            type: String,
            required: true,
            trim: true
        }
    }
});

openStackProviderSchema.statics.createNew = function(providerObj,callback){
    var OpenStackProvider = new baseProvider(providerObj);
    OpenStackProvider.save(function(err, data) {
        if (err) {
            logger.error("createNew Failed", err, data);
            return;
        }
        callback(null,data);
    });
}
openStackProviderSchema.statics.updateOpenStackProviderDetails = function(providerId,providerObj,callback){
    openStackProvider.update({_id:new ObjectId(providerId)},{$set:providerObj},{upsert:false}, function(err, updateOpenStackProvider) {
        if (err) {
            logger.error(err);
            var error = new Error('Internal server error');
            error.status = 500;
            return callback(error);
        }
        return callback(null, updateOpenStackProvider);
    });
};

var openStackProvider = providers.discriminator('openStackProvider', openStackProviderSchema);
module.exports = openStackProvider;
