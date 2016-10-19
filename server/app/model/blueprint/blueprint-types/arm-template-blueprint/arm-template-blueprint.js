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
var extend = require('mongoose-schema-extend');

var Schema = mongoose.Schema;


var ARMTemplateBlueprintSchema = new Schema({
    parameters: {
            type: Object,
            trim: true
    },
    instances: {
        type: Object,
        trim: true
    },
    resourceGroup: {
        type: Object,
        trim: true
    }
});
ARMTemplateBlueprintSchema.statics.createNew = function(azureArmTempData) {
    var parameters = {};

    if (azureArmTempData.stackParameters) {
        for (var i = 0; i < azureArmTempData.stackParameters.length; i++) {
            parameters[azureArmTempData.stackParameters[i].ParameterKey] = {};
            var value = azureArmTempData.stackParameters[i].ParameterValue;
            if (azureArmTempData.stackParameters[i].type === 'int') {
                value = parseFloat(azureArmTempData.stackParameters[i].ParameterValue);
            }
            parameters[azureArmTempData.stackParameters[i].ParameterKey].value = value;
        }
    }
    var cftBlueprint = new ARMTemplateBlueprint({
        infraManagerDetails: cloudFormationData.infraManagerDetails,
        parameters: parameters,
        resourceGroup: azureArmTempData.resourceGroup,
        instances: azureArmTempData.instances
    });


    return cftBlueprint;
};



var ARMTemplateBlueprint = mongoose.model('ARMTemplateBlueprint', ARMTemplateBlueprintSchema);

module.exports = ARMTemplateBlueprint;
