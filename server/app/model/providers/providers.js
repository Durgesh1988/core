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
var ObjectId = require('mongoose').Types.ObjectId;
var mongoosePaginate = require('mongoose-paginate');

var providerSchema = new baseProvider();
providerSchema.plugin(mongoosePaginate);


providerSchema.statics.getAllProviders = function getAllProviders(filterObj, callback) {
    this.paginate(filterObj.queryObj, filterObj.options, function(err, providers) {
            if (err) {
                logger.error(err);
                return callback(err, null);
            } else {
                return callback(null, providers);
            }
        }
    );
};

providerSchema.statics.updateProviderById = function updateById(providerId, fields, callback) {
    this.update({_id: providerId}, fields,
        function(err, result) {
            if (err) {
                return callback(err, null);
            } else if(result.ok == 1 && result.n == 1)  {
                return callback(null, true);
            }
        }
    );
};

providerSchema.statics.getProviderById = function getById(providerId, callback) {
    this.find({'_id': ObjectId(providerId)},
        function(err, providers) {
            if (err) {
                logger.error(err);
                return callback(err, null);
            } else if(providers && providers.length > 0){
                return callback(null, providers[0]);
            } else {
                return callback(null, null);
            }
        }
    );
};

providerSchema.statics.deleteProviderById = function deleteById(providerId, callback) {
    this.remove({'_id': ObjectId(providerId)},
        function(err, provider) {
            if(err) {
                logger.error(err);
                return callback(err, null);
            } else {
                return callback(null, true);
            }
        }
    )
};


var provider = mongoose.model('provider', providerSchema);
module.exports = provider;

