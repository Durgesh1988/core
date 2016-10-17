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

var CloudFormationBlueprintSchema = new Schema({
    stackParameters: [{
        ParameterKey: {
            type: String,
            trim: true
        },
        ParameterValue: {
            type: String,
            trim: true
        }
    }],
    instanceDetails: [{
        logicalId: {
            type: String,
            trim: true
        },
        username: {
            type: String,
            trim: true
        },
        runlist: [{
            type: String,
            trim: true
        }]
    }],
    regionDetails: {
        id: {
            type: String,
            trim: true
        },
        name: {
            type: String,
            trim: true
        }
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

CloudFormationBlueprintSchema.statics.createNew = function(cloudFormationData) {
    var stackParameters = [];
    if (cloudFormationData.stackParameters) {
        for (var i = 0; i < cloudFormationData.stackParameters.length; i++) {
            var parameterObj = {
                ParameterKey: cloudFormationData.stackParameters[i].ParameterKey
            };
            if (cloudFormationData.stackParameters[i].type === 'Number') {
                parameterObj.ParameterValue = parseFloat(cloudFormationData.stackParameters[i].ParameterValue);
            } else {
                parameterObj.ParameterValue = cloudFormationData.stackParameters[i].ParameterValue;
            }
            stackParameters.push(parameterObj);
        }
    }
    var cftBlueprint = new CloudFormationBlueprint({
        infraManagerDetails: cloudFormationData.infraManagerDetails,
        stackParameters: stackParameters,
        instanceDetails: cloudFormationData.instanceDetails,
        regionDetails: cloudFormationData.regionDetails
    });
    return cftBlueprint;
};

var CloudFormationBlueprint = mongoose.model('CloudFormationBlueprint', CloudFormationBlueprintSchema);

module.exports = CloudFormationBlueprint;
