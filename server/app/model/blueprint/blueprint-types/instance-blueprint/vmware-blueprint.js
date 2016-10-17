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
var Schema = mongoose.Schema;


var vmWareInstanceBlueprintSchema = new Schema({
    networkDetails: {
        id: {
            type: String,
            trim: true
        },
        name: {
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
    dataStoreDetails: {
        id: {
            type: String,
            trim: true
        },
        name: {
            type: String,
            trim: true

        }
    },
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
    },
    instanceCount: {
        type: String,
        trim: true
    },
    instanceUsername: {
        type: String,
        trim: true
    },
    infraManagerDetails : {
        id: {
            type: String,
            required: true,
            trim: true
        },
        type: {
            type: String,
            required: true,
            trim: true
        },
        infraManagerData: Schema.Types.Mixed
    }
});



vmWareInstanceBlueprintSchema.statics.createNew = function(vmWareData) {
    var vmWareInstanceBlueprint = new vmWareInstanceBlueprint(vmWareData);
    return vmWareInstanceBlueprint;
};

var vmWareInstanceBlueprint = mongoose.model('vmWareInstanceBlueprint', vmWareInstanceBlueprintSchema);

module.exports = vmWareInstanceBlueprint;
