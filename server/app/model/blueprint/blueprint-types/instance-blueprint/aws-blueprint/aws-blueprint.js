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
var appConfig = require('_pr/config');
var EC2 = require('_pr/lib/ec2.js');
var logsDao = require('_pr/model/dao/logsdao.js');
var Cryptography = require('_pr/lib/utils/cryptography');
var fileIo = require('_pr/lib/utils/fileio');
var uuid = require('node-uuid');
var AWSProvider = require('_pr/model/classes/masters/cloudprovider/awsCloudProvider.js');
var VMImage = require('_pr/model/classes/masters/vmImage.js');
var AWSKeyPair = require('_pr/model/classes/masters/cloudprovider/keyPair.js');
var masterUtil = require('_pr/lib/utils/masterUtil.js');
var Schema = mongoose.Schema;
var resourceService = require('_pr/services/resourceService');
var resourceModel = require('_pr/model/resources/resources');
var serviceMapService = require('_pr/services/serviceMapService');
var auditTrailService = require('_pr/services/auditTrailService');
var noticeService = require('_pr/services/noticeService.js');
var commonService = require('_pr/services/commonService.js');

var AWSInstanceBlueprintSchema = new Schema({
    _id:false,
    keyPairId: {
        type: String,
        required: true,
        trim: true
    },
    subnetId: {
        type: String,
        required: true,
        trim: true
    },
    vpcId: {
        type: String,
        required: true,
        trim: true
    },
    region: {
        type: String,
        required: true,
        trim: true
    },
    securityGroupIds: {
        type: [String],
        required: true,
        trim: true
    },
    instanceType: {
        type: String,
        required: false,
        trim: true
    },
    instanceOS: {
        type: String,
        required: false,
        trim: true
    },
    instanceCount: {
        type: String,
        required: false,
        trim: true
    },
    instanceAmiid: {
        type: String,
        required: false,
        trim: true
    },
    instanceUsername: {
        type: String,
        required: true,
        trim: true
    },
    imageId: {
        type: String,
        required: true,
        trim: true
    }
});

AWSInstanceBlueprintSchema.methods.launch = function (launchParams, callback) {
    var self = this;
    var domainName = launchParams.domainName;
    VMImage.getImageById(self.imageId, function (err, anImage) {
        if (err) {
            logger.error(err);
            return callback({message: "db-error"});
        }
        AWSProvider.getAWSProviderById(anImage.providerId, function (err, aProvider) {
            if (err) {
                logger.error(err);
                return callback({message: "db-error"});
            }
            if (!aProvider) {
                return callback({message: "Unable to fetch provider from DB"});
            }
            AWSKeyPair.getAWSKeyPairById(self.keyPairId, function (err, aKeyPair) {
                if (err) {
                    logger.error(err);
                    return callback({message: "db-error"});
                }
                var awsSettings;
                if (aProvider.isDefault) {
                    awsSettings = {
                        "isDefault": true,
                        "region": aKeyPair.region,
                        "keyPairName": aKeyPair.keyPairName
                    };
                } else {
                    var cryptoConfig = appConfig.cryptoSettings;
                    var cryptography = new Cryptography(cryptoConfig.algorithm,
                        cryptoConfig.password);
                    var decryptedAccessKey = cryptography.decryptText(aProvider.accessKey,
                        cryptoConfig.decryptionEncoding, cryptoConfig.encryptionEncoding);
                    var decryptedSecretKey = cryptography.decryptText(aProvider.secretKey,
                        cryptoConfig.decryptionEncoding, cryptoConfig.encryptionEncoding);
                    awsSettings = {
                        "access_key": decryptedAccessKey,
                        "secret_key": decryptedSecretKey,
                        "region": aKeyPair.region,
                        "keyPairName": aKeyPair.keyPairName
                    };
                }
                var credentials = {
                    username:anImage.userName
                }
                if (anImage.instancePassword && anImage.instancePassword.length) {
                    credentials.password = anImage.instancePassword;
                } else {
                    credentials.fileId = aKeyPair.fileId;
                }
                var securityGroupIds = [];
                for (var i = 0; i < self.securityGroupIds.length; i++) {
                    securityGroupIds.push(self.securityGroupIds[i]);
                }
                var ec2 = new EC2(awsSettings);
                if (!self.instanceCount) {
                    self.instanceCount = "1";
                }
                var instanceIds = [];
                ec2.launchInstance(anImage.imageIdentifier, self.instanceType, securityGroupIds, self.subnetId, 'D4D-' + launchParams.blueprintName, aKeyPair.keyPairName, self.instanceCount, function (err, instanceDataAll) {
                    if (err) {
                        return callback({message: err.message});
                    }
                    for (var i = 0; i < instanceDataAll.length; i++) {
                        addInstanceWrapper(instanceDataAll[i],instanceDataAll.length);
                    }
                    function addInstanceWrapper(instanceData,instanceCount) {
                        var instanceObj = {
                            name: launchParams.blueprintName,
                            masterDetails: {
                                orgId: launchParams.orgId,
                                orgName: launchParams.orgName,
                                bgId: launchParams.bgId,
                                bgName: launchParams.bgName,
                                projectId: launchParams.projectId,
                                projectName: launchParams.projectName,
                                envId: launchParams.envId,
                                envName: launchParams.envName,
                            },
                            providerDetails: {
                                id: launchParams.cloudProviderId,
                                type: launchParams.cloudProviderType,
                                keyPairId: self.keyPairId,
                                region: aKeyPair.region,
                                keyPairName: instanceData.KeyName
                            },
                            resourceDetails: {
                                platformId: instanceData.InstanceId,
                                amiId: instanceData.ImageId,
                                publicIp: instanceData.PublicIpAddress || null,
                                hostName: instanceData.PrivateDnsName,
                                os: (instanceData.Platform && instanceData.Platform === 'windows') ? 'windows' : 'linux',
                                state: instanceData.State.Name,
                                subnetId: instanceData.SubnetId,
                                vpcId: instanceData.VpcId,
                                privateIp: instanceData.PrivateIpAddress,
                                type: instanceData.InstanceType,
                                launchTime: Date.parse(instanceData.LaunchTime),
                                credentials: credentials,
                                bootStrapState:'bootStrapping'
                            },
                            configDetails: {
                                id: launchParams.infraManagerId,
                                nodeName: instanceData.InstanceId
                            },
                            blueprintDetails: {
                                id: launchParams.blueprintData.id ? launchParams.blueprintData.blueprintId : null,
                                name: launchParams.blueprintData.blueprintName ? launchParams.blueprintData.blueprintName : null,
                                templateName: launchParams.blueprintData.templateId ? launchParams.blueprintData.templateId : null,
                                templateType: launchParams.blueprintData.templateType ? launchParams.blueprintData.templateType : null
                            },
                            resourceType: 'EC2',
                            category: "managed",
                            authentication: 'success',
                            stackName: launchParams.domainName && launchParams.domainName !== null ? launchParams.domainName : launchParams.stackName,
                            tagServer: launchParams.tagServer,
                            monitor: launchParams.monitor,
                            user:launchParams.sessionUser
                        }
                        instanceObj.createdOn = new Date().getTime();
                        var queryObj = {
                            'masterDetails.orgId': instanceObj.masterDetails.orgId,
                            'providerDetails.id': instanceObj.providerDetails.id,
                            'resourceDetails.platformId': instanceObj.resourceDetails.platformId
                        }
                        resourceModel.getResources(queryObj,function(err,resourceDetails){
                            if(err){
                                logger.error("Error in fetching resource Details:",err);
                            }
                            if(resourceDetails.length > 0){
                                resourceModel.updateResourceById(resourceDetails[0]._id,instanceObj, function (err, resource){
                                    if (err) {
                                        logger.error("Error in updating Resources>>>>:", err);
                                    }
                                    createInstance(resourceDetails);
                                })
                            }else{
                                resourceModel.createNew(instanceObj, function (err, resource){
                                    if (err) {
                                        logger.error("Error in creating Resources>>>>:", err);
                                    }
                                    createInstance(resource);
                                })
                            }
                        });
                        function createInstance(resource) {
                            instanceIds.push(resource._id);
                            if(instanceIds.length = instanceCount){
                                callback(null, {
                                    "id": instanceIds,
                                    "message": "instance launch success"
                                });
                            }
                            if (launchParams.serviceMapObj) {
                                var serviceObj = launchParams.serviceMapObj;
                                var ymlText = {
                                    aws: {
                                        groups: [{
                                            name: launchParams.blueprintName,
                                            identifiers: {
                                                ip: [instanceData.PrivateIpAddress],
                                                subnet: [instanceData.SubnetId],
                                                vpc: [instanceData.VpcId]
                                            }
                                        }]
                                    }
                                }
                                var mkDir = require('mkdirp');
                                var fileUpload = require('_pr/model/file-upload/file-upload');
                                var async = require('async');
                                var path = require('path');
                                var yml = require('json2yaml');
                                var ymlFolderName = appConfig.tempDir;
                                var ymlFileName = resource._id + '.yaml';
                                var ymlFolder = path.normalize(ymlFolderName);
                                mkDir.sync(ymlFolder);
                                ymlText = yml.stringify(ymlText);
                                async.waterfall([
                                    function (next) {
                                        fileIo.writeFile(ymlFolder + '/' + ymlFileName, ymlText, null, next);
                                    },
                                    function (next) {
                                        fileUpload.uploadFile(resource._id + '.yaml', ymlFolder + '/' + ymlFileName, null, next);
                                    }
                                ], function (err, results) {
                                    if (err) {
                                        logger.error(err);
                                        fileIo.removeFile(ymlFolder + '/' + ymlFileName, function (err, removeCheck) {
                                            if (err) {
                                                logger.error(err);
                                            } else {
                                                logger.debug("Successfully remove YML file");
                                            }
                                        })
                                    } else {
                                        serviceObj.fileId = results;
                                        serviceMapService.createNewService(serviceObj, function (err, data) {
                                            if (err) {
                                                logger.error("Error in creating Service Map Service:", err);
                                            }
                                            fileIo.removeFile(ymlFolder + '/' + ymlFileName, function (err, removeCheck) {
                                                if (err) {
                                                    logger.error(err);
                                                } else {
                                                    logger.debug("Successfully remove YML file");
                                                }
                                            })
                                        })
                                    }
                                })
                            }
                            var actionId =uuid.v4();
                            var timestampStarted = new Date().getTime();
                            if (launchParams.auditTrailId !== null) {
                                var resultTaskExecution = {
                                    "actionLogId": launchParams.actionLogId,
                                    "auditTrailConfig.nodeIdsWithActionLog": [{
                                        "actionLogId": actionId,
                                        "nodeId": resource._id
                                    }],
                                    "auditTrailConfig.nodeIds": [resource._id],
                                    "masterDetails.orgName": launchParams.orgName,
                                    "masterDetails.bgName": launchParams.bgName,
                                    "masterDetails.projectName": launchParams.projectName,
                                    "masterDetails.envName": launchParams.envName
                                }
                                auditTrailService.updateAuditTrail(launchParams.auditType, launchParams.auditTrailId, resultTaskExecution, function (err, auditTrail) {
                                    if (err) {
                                        logger.error("Failed to create or update bots Log: ", err);
                                    }
                                });
                            }
                            var logData = {
                                instanceId: resource._id,
                                instanceRefId: actionId,
                                botId: launchParams.botId,
                                botRefId: launchParams.actionLogId,
                                err: false,
                                log: "Starting instance",
                                timestamp: timestampStarted
                            };
                            logsDao.insertLog(logData);
                            noticeService.updater(launchParams.actionLogId, 'log', logData);
                            ec2.waitForInstanceRunnnigState(resource.resourceDetails.platformId, function (err, instanceData) {
                                if (err) {
                                    var timestamp = new Date().getTime();
                                    if (launchParams.auditTrailId !== null) {
                                        var resultTaskExecution = {
                                            actionStatus: "failed",
                                            status: "failed",
                                            endedOn: new Date().getTime(),
                                            actionLogId: launchParams.actionLogId
                                        }
                                        auditTrailService.updateAuditTrail(launchParams.auditType, launchParams.auditTrailId, resultTaskExecution, function (err, auditTrail) {
                                            if (err) {
                                                logger.error("Failed to create or update bots Log: ", err);
                                            }
                                        });
                                    }
                                    var logData = {
                                        instanceId: resource._id,
                                        instanceRefId: actionId,
                                        botId: launchParams.botId,
                                        botRefId: launchParams.actionLogId,
                                        err: true,
                                        log: "Instance ready state wait failed. Unable to bootstrap",
                                        timestamp: timestamp
                                    };
                                    logsDao.insertLog(logData);
                                    noticeService.updater(launchParams.actionLogId, 'log', logData);
                                    noticeService.notice(launchParams.sessionUser, {
                                        title: "Blueprint BOTs Execution",
                                        body: "Instance ready state wait failed. Unable to bootstrap"
                                    }, "error", function (err, data) {
                                        if (err) {
                                            logger.error("Error in Notification Service, ", err);
                                        }
                                    });
                                    logger.error("waitForInstanceRunnnigState returned an error  >>", err);
                                    return;
                                }else{
                                    var resourceDetails = {
                                        id:resource._id,
                                        actionId:actionId,
                                        botId:launchParams.botId?launchParams.botId:null,
                                        botRefId: launchParams.actionLogId?launchParams.actionLogId:null
                                    }
                                    commonService.bootStrappingResource(resourceDetails,function(err,data){
                                        if(err){
                                            logger.error(err);
                                            if (launchParams.auditTrailId !== null) {
                                                var resultTaskExecution = {
                                                    actionStatus: "failed",
                                                    status: "failed",
                                                    endedOn: new Date().getTime(),
                                                    actionLogId: launchParams.actionLogId
                                                }
                                                auditTrailService.updateAuditTrail(launchParams.auditType, launchParams.auditTrailId, resultTaskExecution, function (err, auditTrail) {
                                                    if (err) {
                                                        logger.error("Failed to create or update bots Log: ", err);
                                                    }
                                                });
                                            }
                                        }else{
                                            if (launchParams.auditTrailId !== null) {
                                                var resultTaskExecution = {
                                                    actionStatus: "success",
                                                    status: "success",
                                                    endedOn: new Date().getTime(),
                                                    actionLogId: launchParams.actionLogId
                                                }
                                                auditTrailService.updateAuditTrail(launchParams.auditType, launchParams.auditTrailId, resultTaskExecution, function (err, auditTrail) {
                                                    if (err) {
                                                        logger.error("Failed to create or update bots Log: ", err);
                                                    }
                                                });
                                            }
                                        }
                                    })
                                }
                            });
                        }
                    }
                });
            });
        });
    });
};

AWSInstanceBlueprintSchema.statics.createNew = function (awsData) {
    var self = this;
    var awsInstanceBlueprint = new self(awsData);
    return awsInstanceBlueprint;
};
var AWSInstanceBlueprint = mongoose.model('AWSInstanceBlueprint', AWSInstanceBlueprintSchema);

module.exports = AWSInstanceBlueprint;