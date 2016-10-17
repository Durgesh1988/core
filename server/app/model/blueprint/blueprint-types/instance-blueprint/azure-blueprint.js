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

var AzureInstanceBlueprintSchema = new Schema({
    keyPairDetails: {
        id: {
            type: String,
            required: true,
            trim: true
        },
        name: {
            type: String,
            required: true,
            trim: true
        }
    },
    subnetDetails: {
        id: {
            type: String,
            required: true,
            trim: true
        },
        name: {
            type: String,
            required: true,
            trim: true
        }
    },
    vpcDetails: {
        id: {
            type: String,
            required: true,
            trim: true
        },
        name: {
            type: String,
            required: true,
            trim: true
        }
    },
    regionDetails: {
        id: {
            type: String,
            required: true,
            trim: true
        },
        name: {
            type: String,
            required: true,
            trim: true
        }
    },
    securityGroupDetails: [{
        id: {
            type: String,
            required: true,
            trim: true
        },
        name: {
            type: String,
            required: true,
            trim: true
        }
    }],
    instanceType: {
        type: String,
        trim: true
    },
    instanceOS: {
        type: String,
        trim: true
    },
    instanceCount: {
        type: Number,
        default: 1
    },
    instanceAmiId: {
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

AzureInstanceBlueprintSchema.statics.createNew = function(azureData) {
    var self = this;
    var azureInstanceBlueprint = new self(azureData);
    return azureInstanceBlueprint;
};

var AzureInstanceBlueprint = mongoose.model('AzureInstanceBlueprint', AzureInstanceBlueprintSchema);
module.exports = AzureInstanceBlueprint;
