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
var Schema = mongoose.Schema;

var openStackInstanceBlueprintSchema = new Schema({
    flavorDetails: {
        id : {
            type: String,
            trim: true
        },
        name : {
            type: String,
            trim: true
        }
    },
    networkDetails: {
        id : {
            type: String,
            trim: true
        },
        name : {
            type: String,
            trim: true
        }
    },
    securityGroupDetails: [{
        id: {
            type: String,
            trim: true
        },
        name: {
            type: String,
            trim: true
        }
    }],
    subnetDetails: {
        id: {
            type: String,
            trim: true
        },
        name: {
            type: String,
            trim: true
        }
    },
    instanceOS: {
        type: String,
        trim: true
    },
    instanceCount: {
        type: String,
        trim: true
    },
    instanceUsername: {
        type: String,
        trim: true
    }
});

openStackInstanceBlueprintSchema.statics.createNew = function(openStackData) {
    var openStackInstanceBlueprint = new openStackInstanceBlueprint(openStackData);
    return openStackInstanceBlueprint;
};

var openStackInstanceBlueprint = mongoose.model('openStackInstanceBlueprint', openStackInstanceBlueprintSchema);
module.exports = openStackInstanceBlueprint;