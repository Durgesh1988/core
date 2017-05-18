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


var vmWareProviderSchema = new baseProvider({
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
        dc: {
            type: String,
            required: true,
            trim: true
        }
    }
});

vmWareProviderSchema.statics.createNew = function(providerObj,callback){
    var VMWareProvider = new baseProvider(providerObj);
    VMWareProvider.save(function(err, data) {
        if (err) {
            logger.error("createNew Failed", err, data);
            return;
        }
        callback(null,data);
    });
}
vmWareProviderSchema.statics.updateVmWareProviderDetails = function(providerId,providerObj,callback){
    vmwareProvider.update({_id:new ObjectId(providerId)},{$set:providerObj},{upsert:false}, function(err, updateVmWareProvider) {
        if (err) {
            logger.error(err);
            var error = new Error('Internal server error');
            error.status = 500;
            return callback(error);
        }
        return callback(null, updateVmWareProvider);
    });
};

var vmWareProvider = providers.discriminator('vmWareProvider', vmWareProviderSchema);
module.exports = vmWareProvider;
