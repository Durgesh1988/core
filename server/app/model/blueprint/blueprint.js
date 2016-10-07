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
    isDeleted: {
        type: Boolean,
        default: false
    },
    createdOn:{
        type:String,
        default:Date.now
    }
});

BlueprintSchema.plugin(mongoosePaginate);

function getBlueprintConfigType(blueprint) {
    var BlueprintConfigType;
    if ((blueprint.blueprintType === BLUEPRINT_TYPE.INSTANCE_LAUNCH) && blueprint.blueprintConfig) {
        BlueprintConfigType = InstanceBlueprint;
    } else if ((blueprint.blueprintType === BLUEPRINT_TYPE.DOCKER) && blueprint.blueprintConfig) {
        BlueprintConfigType = DockerBlueprint;
    } else if ((blueprint.blueprintType === BLUEPRINT_TYPE.AWS_CLOUDFORMATION) && blueprint.blueprintConfig) {
        BlueprintConfigType = CloudFormationBlueprint;
    } else if ((blueprint.blueprintType === BLUEPRINT_TYPE.AZURE_ARM_TEMPLATE) && blueprint.blueprintConfig) {
        BlueprintConfigType = ARMTemplateBlueprint;
    } else if ((blueprint.blueprintType === BLUEPRINT_TYPE.OPENSTACK_LAUNCH || blueprint.blueprintType === BLUEPRINT_TYPE.HPPUBLICCLOUD_LAUNCH) && blueprint.blueprintConfig) {
        BlueprintConfigType = OpenstackBlueprint;
    } else if ((blueprint.blueprintType === BLUEPRINT_TYPE.AZURE_LAUNCH) && blueprint.blueprintConfig) {
        BlueprintConfigType = AzureBlueprint;
    } else if ((blueprint.blueprintType === BLUEPRINT_TYPE.VMWARE_LAUNCH) && blueprint.blueprintConfig) {
        logger.debug('this is test');
        BlueprintConfigType = VmwareBlueprint;
    } else {
        return;
    }
    var blueprintConfigType = new BlueprintConfigType(blueprint.blueprintConfig);
    return blueprintConfigType;
}

BlueprintSchema.methods.update = function(updateData, callback) {
    var blueprintConfigType = getBlueprintConfigType(this);
    if (!blueprintConfigType) {
        process.nextTick(function() {
            callback({
                message: "Invalid Blueprint Type"
            }, null);
        });
    }
    blueprintConfigType.update(updateData);
    this.blueprintConfig = blueprintConfigType;
    this.save(function(err, updatedBlueprint) {
        if (err) {
            callback(err, null);
            return;
        }
        callback(null, updatedBlueprint);
    });
};

BlueprintSchema.methods.getVersionData = function(ver) {
    var blueprintConfigType = getBlueprintConfigType(this);
    if (!blueprintConfigType) {
        return null;
    }

    return blueprintConfigType.getVersionData(ver);
};

BlueprintSchema.methods.getLatestVersion = function() {
    var blueprintConfigType = getBlueprintConfigType(this);
    if (!blueprintConfigType) {
        return null;
    }

    return blueprintConfigType.getLatestVersion();
};

BlueprintSchema.methods.getInfraManagerData = function() {
    var blueprintConfigType = getBlueprintConfigType(this);
    if (!blueprintConfigType) {
        return null;
    }

    return blueprintConfigType.getInfraManagerData();
}

BlueprintSchema.methods.getCloudProviderData = function() {
    var blueprintConfigType = getBlueprintConfigType(this);
    if (!blueprintConfigType) {
        return null;
    }

    return blueprintConfigType.getCloudProviderData();
}

BlueprintSchema.methods.launch = function(opts, callback) {
    var infraManager = this.getInfraManagerData();
    var self = this;
    masterUtil.getParticularProject(self.projectId, function(err, project) {
        if (err) {
            callback({
                message: "Failed to get project via project id"
            }, null);
            return;
        };
        if (project.length === 0) {
            callback({
                "message": "Unable to find Project Information from project id"
            });
            return;
        }
        configmgmtDao.getEnvNameFromEnvId(opts.envId, function(err, envName) {
            if (err) {
                callback({
                    message: "Failed to get env name from env id"
                }, null);
                return;
            };
            if (!envName) {
                callback({
                    "message": "Unable to find environment name from environment id"
                });
                return;
            };
            configmgmtDao.getChefServerDetails(infraManager.infraManagerId, function(err, chefDetails) {
                if (err) {
                    logger.error("Failed to getChefServerDetails", err);
                    callback({
                        message: "Failed to getChefServerDetails"
                    }, null);
                    return;
                };
                if (!chefDetails) {
                    logger.error("No CHef Server Detailed available.", err);
                    callback({
                        message: "No Chef Server Detailed available"
                    }, null);
                    return;
                };
                var chef = new Chef({
                    userChefRepoLocation: chefDetails.chefRepoLocation,
                    chefUserName: chefDetails.loginname,
                    chefUserPemFile: chefDetails.userpemfile,
                    chefValidationPemFile: chefDetails.validatorpemfile,
                    hostedChefUrl: chefDetails.url
                });
                logger.debug('Chef Repo Location = ', chefDetails.chefRepoLocation);
                var blueprintConfigType = getBlueprintConfigType(self);
                if (!self.appUrls) {
                    self.appUrls = [];
                }
                var appUrls = self.appUrls;
                if (appConfig.appUrls && appConfig.appUrls.length) {
                    appUrls = appUrls.concat(appConfig.appUrls);
                }
                chef.getEnvironment(envName, function(err, env) {
                    if (err) {
                        logger.error("Failed chef.getEnvironment", err);
                        callback(err, null);
                        return;
                    }
                    if (!env) {
                        chef.createEnvironment(envName, function(err) {
                            if (err) {
                                logger.error("Failed chef.createEnvironment", err);
                                callback(err, null);
                                return;
                            }
                            blueprintConfigType.launch({
                                infraManager: chef,
                                ver: opts.ver,
                                envName: envName,
                                envId: opts.envId,
                                stackName: opts.stackName,
                                domainName:opts.domainName,
                                blueprintName: self.name,
                                orgId: self.orgId,
                                orgName: project[0].orgname,
                                bgId: self.bgId,
                                bgName: project[0].productgroupname,
                                projectId: self.projectId,
                                projectName: project[0].projectname,
                                appUrls: appUrls,
                                sessionUser: opts.sessionUser,
                                users: self.users,
                                blueprintData: self,
                            }, function(err, launchData) {
                                callback(err, launchData);
                            });
                        });
                    } else {
                        blueprintConfigType.launch({
                            infraManager: chef,
                            ver: opts.ver,
                            envName: envName,
                            envId: opts.envId,
                            stackName: opts.stackName,
                            domainName:opts.domainName,
                            blueprintName: self.name,
                            orgId: self.orgId,
                            orgName: project[0].orgname,
                            bgId: self.bgId,
                            bgName: project[0].productgroupname,
                            projectId: self.projectId,
                            projectName: project[0].projectname,
                            appUrls: appUrls,
                            sessionUser: opts.sessionUser,
                            users: self.users,
                            blueprintData: self,
                        }, function(err, launchData) {
                            callback(err, launchData);
                        });
                    }
                });
            });
        });
    });
};

// static methods
BlueprintSchema.statics.createNew = function(blueprintData, callback) {
  

    var blueprintConfig, blueprintType;
    if ((blueprintData.blueprintType === BLUEPRINT_TYPE.INSTANCE_LAUNCH) && blueprintData.instanceData) {
        blueprintType = BLUEPRINT_TYPE.INSTANCE_LAUNCH;
        blueprintConfig = InstanceBlueprint.createNew(blueprintData.instanceData);
    } else if ((blueprintData.blueprintType === BLUEPRINT_TYPE.DOCKER) && blueprintData.dockerData) {
        blueprintType = BLUEPRINT_TYPE.DOCKER;
        blueprintConfig = DockerBlueprint.createNew(blueprintData.dockerData);
    } else if ((blueprintData.blueprintType === BLUEPRINT_TYPE.AWS_CLOUDFORMATION) && blueprintData.cloudFormationData) {
        blueprintType = BLUEPRINT_TYPE.AWS_CLOUDFORMATION;
        blueprintConfig = CloudFormationBlueprint.createNew(blueprintData.cloudFormationData);
    } else if ((blueprintData.blueprintType === BLUEPRINT_TYPE.AZURE_ARM_TEMPLATE) && blueprintData.armTemplateData) {
        blueprintType = BLUEPRINT_TYPE.AZURE_ARM_TEMPLATE;
        blueprintConfig = ARMTemplateBlueprint.createNew(blueprintData.armTemplateData);
    } else if ((blueprintData.blueprintType === BLUEPRINT_TYPE.OPENSTACK_LAUNCH) && blueprintData.instanceData) {
        blueprintType = BLUEPRINT_TYPE.OPENSTACK_LAUNCH;
        logger.debug('blueprintData openstack instacedata ==>', blueprintData.instanceData);
        blueprintConfig = OpenstackBlueprint.createNew(blueprintData.instanceData);
    } else if ((blueprintData.blueprintType === BLUEPRINT_TYPE.HPPUBLICCLOUD_LAUNCH) && blueprintData.instanceData) {
        blueprintType = BLUEPRINT_TYPE.HPPUBLICCLOUD_LAUNCH;
        logger.debug('blueprintData openstack instacedata ==>', blueprintData.instanceData);
        blueprintConfig = OpenstackBlueprint.createNew(blueprintData.instanceData);
    } else if ((blueprintData.blueprintType === BLUEPRINT_TYPE.AZURE_LAUNCH) && blueprintData.instanceData) {
        blueprintType = BLUEPRINT_TYPE.AZURE_LAUNCH;
        logger.debug('blueprintData azure instacedata ==>', blueprintData.instanceData);
        blueprintConfig = AzureBlueprint.createNew(blueprintData.instanceData);
        blueprintConfig.cloudProviderData = AzureBlueprint.createNew(blueprintData.instanceData);
    } else if ((blueprintData.blueprintType === BLUEPRINT_TYPE.VMWARE_LAUNCH) && blueprintData.instanceData) {
        blueprintType = BLUEPRINT_TYPE.VMWARE_LAUNCH;
        logger.debug('blueprintData vmware instacedata ==>', blueprintData.instanceData);
        blueprintConfig = VmwareBlueprint.createNew(blueprintData.instanceData);

    } else {
        process.nextTick(function() {
            callback({
                message: "Invalid Blueprint Type sdds"
            }, null);
        });
        return;
    }
    logger.debug('blueprint id ..... ', blueprintData.id);
    this.getCountByParentId(blueprintData.id, function(err, count) {
        if (count <= 0) {
            count = 1;
        } else {
            count++;
        }
        var blueprintObj = {
            orgId: blueprintData.orgId,
            bgId: blueprintData.bgId,
            projectId: blueprintData.projectId,
            name: blueprintData.name,
            appUrls: blueprintData.appUrls,
            iconpath: blueprintData.iconpath,
            templateId: blueprintData.templateId,
            templateType: blueprintData.templateType,
            users: blueprintData.users,
            blueprintConfig: blueprintConfig,
            blueprintType: blueprintType,
            nexus: blueprintData.nexus,
            docker: blueprintData.docker,
            version: count,
            parentId: blueprintData.id,
            domainNameCheck: blueprintData.domainNameCheck
        };
        var blueprint = new Blueprints(blueprintObj);
        logger.debug(blueprint);
        logger.debug('saving');
        blueprint.save(function(err, blueprint) {
            if (err) {
                logger.error(err);
                callback(err, null);
                return;
            }
            logger.debug('save Complete');
            callback(null, blueprint);
        });
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

BlueprintSchema.statics.getCountByParentId = function(parentid, callback) {
    if (parentid) {
        this.find({
            $or: [{
                parentId: parentid
            }, {
                _id: ObjectId(parentid)
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
    }, function(err, blueprints) {
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
