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
var extend = require('mongoose-schema-extend');
var ObjectId = require('mongoose').Types.ObjectId;
var mongoosePaginate = require('mongoose-paginate');

var Chef = require('_pr/lib/chef.js');
var configmgmtDao = require('_pr/model/d4dmasters/configmgmt');
var appConfig = require('_pr/config');

var schemaValidator = require('_pr/model/utils/schema-validator');

var uniqueValidator = require('mongoose-unique-validator');

var DockerBlueprint = require('./blueprint-types/docker-blueprint/docker-blueprint');
var InstanceBlueprint = require('./blueprint-types/instance-blueprint/instance-blueprint');
var OpenstackBlueprint = require('./blueprint-types/instance-blueprint/openstack-blueprint/openstack-blueprint');
var AzureBlueprint = require('./blueprint-types/instance-blueprint/azure-blueprint/azure-blueprint');
var VmwareBlueprint = require('./blueprint-types/instance-blueprint/vmware-blueprint/vmware-blueprint');

var CloudFormationBlueprint = require('./blueprint-types/cloud-formation-blueprint/cloud-formation-blueprint');
var ARMTemplateBlueprint = require('./blueprint-types/arm-template-blueprint/arm-template-blueprint');
var utils = require('../classes/utils/utils.js');
var nexus = require('_pr/lib/nexus.js');
var masterUtil = require('_pr/lib/utils/masterUtil.js');

var AWSKeyPair = require('../../model/classes/masters/cloudprovider/keyPair.js');
var VMImage = require('../../model/classes/masters/vmImage.js');
var AWSProvider = require('_pr/model/classes/masters/cloudprovider/awsCloudProvider.js');
var AzureProvider = require('_pr/model/classes/masters/cloudprovider/azureCloudProvider.js');
var VmwareProvider = require('_pr/model/classes/masters/cloudprovider/vmwareCloudProvider.js');
var OpenStackProvider = require('_pr/model/classes/masters/cloudprovider/openstackCloudProvider.js');


var uuid = require('node-uuid');
var AppData = require('_pr/model/app-deploy/app-data');

var BLUEPRINT_TYPE = {
    DOCKER: 'docker',
    AWS_CLOUDFORMATION: 'aws_cf',
    INSTANCE_LAUNCH: "instance_launch",
    OPENSTACK_LAUNCH: "openstack_launch",
    HPPUBLICCLOUD_LAUNCH: "hppubliccloud_launch",
    AZURE_LAUNCH: "azure_launch",
    VMWARE_LAUNCH: "vmware_launch",
    AZURE_ARM_TEMPLATE: "azure_arm"
};

var Schema = mongoose.Schema;

var BlueprintSchema = new Schema({
    masterDetails: {
        orgId: {
            type: String,
            required: false,
            trim: true,
            validate: schemaValidator.orgIdValidator
        },
        orgName: {
            type: String,
            required: false,
            trim: true
        },
        bgId: {
            type: String,
            required: false,
            trim: true,
            validate: schemaValidator.bgIdValidator
        },
        bgName: {
            type: String,
            required: false,
            trim: true
        },
        projectId: {
            type: String,
            required: false,
            trim: true,
            validate: schemaValidator.projIdValidator
        },
        projectName: {
            type: String,
            required: false,
            trim: true
        }
    },
    providerDetails: {
        id: {
            type: String,
            required: false,
            trim: true
        },
        name: {
            type: String,
            required: false,
            trim: true
        },
        type: {
            type: String,
            required: false,
            trim: true
        }
    },
    imageDetails:{
        id: {
            type: String,
            required: false,
            trim: true
        },
        name: {
            type: String,
            required: false,
            trim: true
        }
    },
    blueprintName: {
        type: String,
        required: true,
        trim: true,
        validate: schemaValidator.blueprintNameValidator
    },
    blueprintType: {
        type: String,
        required: true,
        trim: true
    },
    serverDetails: {
        id: {
            type: String,
            required: false,
            trim: true
        },
        name: {
            type: String,
            required: false,
            trim: true
        },
        repoId: {
            type: String,
            required: false,
            trim: true
        },
        serverType:{
            type: String,
            required: false,
            trim: true
        },
        serverConfiguration:Schema.Types.Mixed
    },
    templateDetails: {
        id: {
            type: String,
            required: false,
            trim: true
        },
        name: {
            type: String,
            required: false,
            trim: true
        },
        type: {
            type: String,
            required: false,
            trim: true
        }
    },
    blueprintConfig: Schema.Types.Mixed,
    version: {
        type: String,
        required: true,
        trim: true,
    },
    parentId: {
        type: String,
        required: false
    },
    iconPath: {
        type: String,
        trim: true,
        required: false
    },
    domainNameCheck:{
        type:Boolean,
        required:false,
        default:false
    },
    shortDesc: {
        type: String,
        trim: true
    },
    botType: {
        type: String,
        trim: true,
    },
    isDeleted: {
        type: Boolean,
        default: false
    },
    createdOn: {
        type: String,
        default: Date.now
    }
});

BlueprintSchema.plugin(mongoosePaginate);

BlueprintSchema.statics.createNew = function(blueprintData, callback) {
    var blueprint = new Blueprints(blueprintData);
    blueprint.save(function(err, blueprint) {
        if (err) {
            logger.error(err);
            callback(err, null);
            return;
        }
        callback(null, blueprint);
    });
};


BlueprintSchema.statics.getById = function(id, callback) {
    this.findById(id, function(err, blueprint) {
        if (err) {
            callback(err, null);
            return;
        }
        callback(null, blueprint);
        return;
    });
};

BlueprintSchema.statics.getBlueprintById = function(blueprintId, callback) {
    this.find({_id: ObjectId(blueprintId)}, function(err, blueprint) {
        if (err) {
            callback(err, null);
            return;
        }
        callback(null, blueprint);
        return;
    });
};

BlueprintSchema.statics.getBlueprintByIds = function(blueprintIds, callback) {
    var ids = [];
    blueprintIds.forEach(function(v) {
        ids.push(ObjectId(v));
    });
    this.find({
        "_id": {
            $in: ids
        }
    }, function(err, blueprints) {
        if (err) {
            callback(err, null);
            return;
        }
        callback(null, blueprints);
        return;
    });
};

BlueprintSchema.statics.getCountByParentId = function(parentId, callback) {
    if (parentId) {
        this.find({
            $or: [{
                parentId: parentId
            }, {
                _id: ObjectId(parentId)
            }]
        }, function(err, blueprint) {
            if (err) {
                callback(err, null);
                return;
            } else {
                callback(null, blueprint.length);
                return;
            }
        });
    } else {
        callback(null, 0);
        return;
    }
};

BlueprintSchema.statics.getByIds = function(ids, callback) {
    this.find({
        "_id": {
            $in: ids
        }
    }, function(err, blueprints) {
        if (err) {
            callback(err, null);
            return;
        }
        callback(null, blueprints);
        return;
    });
};

BlueprintSchema.statics.removeById = function(id, callback) {
    this.remove({
        $or: [{
            "_id": ObjectId(id)
        }, {
            "parentId": id
        }]
    }, function(err, data) {
        if (err) {
            callback(err, null);
            return;
        }
        callback(null, data);
    });
};


BlueprintSchema.statics.getBlueprintsByOrgBgProject = function(jsonData, callback) {
    this.find(jsonData, function(err, blueprints) {
        if (err) {
            callback(err, null);
            return;
        }
        callback(null, blueprints);

    });
};

BlueprintSchema.statics.getBlueprintsByProviderId = function(providerId, callback) {
    this.find({
        "providerDetails.id": providerId
    },function(err, blueprints) {
        if (err) {
            logger.error(err);
            callback(err, null);
            return;
        }
        callback(null, blueprints);
    });
};
BlueprintSchema.statics.getBlueprintByOrgBgProjectProviderType = function(query, callback) {
    Blueprints.paginate(query.queryObj, query.options, function(err, blueprints) {
        if (err) {
            callback(err, null);
            return;
        }
        callback(null, blueprints);
    });
};


BlueprintSchema.statics.checkBPDependencyByFieldName = function(fieldName,id, callback) {
    var queryObj = {};
    queryObj[fieldName] = id;
    Blueprints.find(queryObj, function(err, data) {
        if (err) {
            callback(err, null);
            return;
        }
        callback(null, data);
    });
};

var Blueprints = mongoose.model('blueprints', BlueprintSchema);

module.exports = Blueprints;
