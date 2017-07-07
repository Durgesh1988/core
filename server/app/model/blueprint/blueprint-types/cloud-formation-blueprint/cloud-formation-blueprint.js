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
var EC2 = require('_pr/lib/ec2.js');
var logsDao = require('_pr/model/dao/logsdao.js');
var appConfig = require('_pr/config');
var Cryptography = require('_pr/lib/utils/cryptography');
var fileIo = require('_pr/lib/utils/fileio');
var uuid = require('node-uuid');
var AWSProvider = require('_pr/model/classes/masters/cloudprovider/awsCloudProvider.js');
var credentialcryptography = require('_pr/lib/credentialcryptography');
var CloudFormation = require('_pr/model/cloud-formation');
var AWSCloudFormation = require('_pr/lib/awsCloudFormation.js');
var AwsAutoScaleInstance = require('_pr/model/aws-auto-scale-instance');
var AWSKeyPair = require('_pr/model/classes/masters/cloudprovider/keyPair.js');
var auditTrailService = require('_pr/services/auditTrailService');
var masterUtil = require('_pr/lib/utils/masterUtil.js');
var noticeService = require('_pr/services/noticeService.js');
var serviceMapService = require('_pr/services/serviceMapService');
var resourceModel = require('_pr/model/resources/resources');
var commonService = require('_pr/services/commonService.js');


var CHEFInfraBlueprint = require('./chef-infra-manager/chef-infra-manager');

var Schema = mongoose.Schema;

var INFRA_MANAGER_TYPE = {
    CHEF: 'chef',
    PUPPET: 'puppet'
};


var CloudFormationBlueprintSchema = new Schema({
    _id:false,
    cloudProviderId: String,
    cloudProviderType: {
        type: String,
        "default": 'aws'
    },
    infraMangerType: String,
    infraManagerId: String,
    templateFile: String,
    stackParameters: [{
        _id: false,
        ParameterKey: {
            type: String,
            trim: true
        },
        ParameterValue: {
            type: String,
            trim: true
        }
    }],
    instances: [{
        _id: false,
        logicalId: String,
        username: String,
        runlist: [String]
    }],
    templateFile: String,
    region: String,
});

function getInfraManagerConfigType(blueprint) {
    var InfraManagerConfig;
    if (blueprint.infraMangerType === INFRA_MANAGER_TYPE.CHEF) {
        InfraManagerConfig = CHEFInfraBlueprint;
    } else if (blueprint.infraMangerType === INFRA_MANAGER_TYPE.PUPPET) {
        return null;
    } else {
        return null;
    }
    var infraManagerConfig = new InfraManagerConfig(blueprint.infraManagerData);
    return infraManagerConfig;
}

CloudFormationBlueprintSchema.methods.launch = function (launchParams, callback) {
    var self = this;
    var nodeIdWithActionLogId = [];
    var ymlText = {
        aws:{
            groups:[]
        }
    };
    AWSProvider.getAWSProviderById(self.cloudProviderId, function (err, aProvider) {
        if (err) {
            logger.error("Unable to fetch provide", err);
            return callback({message: "Unable to fetch provider"});
        }
        var cryptoConfig = appConfig.cryptoSettings;
        var cryptography = new Cryptography(cryptoConfig.algorithm,
            cryptoConfig.password);

        var awsSettings;
        if (aProvider.isDefault) {
            awsSettings = {
                "isDefault": true,
                "region": self.region
            };
        } else {

            var decryptedAccessKey = cryptography.decryptText(aProvider.accessKey,
                cryptoConfig.decryptionEncoding, cryptoConfig.encryptionEncoding);
            var decryptedSecretKey = cryptography.decryptText(aProvider.secretKey,
                cryptoConfig.decryptionEncoding, cryptoConfig.encryptionEncoding);

            awsSettings = {
                "access_key": decryptedAccessKey,
                "secret_key": decryptedSecretKey,
                "region": self.region
            };
        }
        var templateFile = self.templateFile;
        var settings = appConfig.chef;
        var chefRepoPath = settings.chefReposLocation;
        fileIo.readFile(chefRepoPath + 'catalyst_files/' + templateFile, function (err, fileData) {
            if (err) {
                logger.error("Unable to read template file " + templateFile, err);
                return callback({message: "Unable to read template file"});
            }
            if (typeof fileData === 'object') {
                fileData = fileData.toString('ascii');
            }
            var awsCF = new AWSCloudFormation(awsSettings);
            awsCF.createStack({
                name: launchParams.stackName,
                templateParameters: JSON.parse(JSON.stringify(self.stackParameters)),
                templateBody: fileData
            }, function (err, stackData) {
                if (err) {
                    logger.error("Unable to launch CloudFormation Stack", err);
                    return callback({message: "Unable to launch CloudFormation Stack"});
                }
                if(launchParams.actionLogId !== null) {                    
                    var logData ={
                        botId:launchParams.botId,
                        botRefId: launchParams.actionLogId,
                        err: false,
                        log: "BOT Execution has started for Blueprint BOT :"+launchParams.bot_id,
                        timestamp: new Date().getTime()
                    };
                    logsDao.insertLog(logData);
                    noticeService.updater(launchParams.actionLogId,'log',logData);
                    logData.log = "Stack created name: " + launchParams.stackName +"  id: "+stackData.StackId;
                    logData.timestamp = new Date().getTime();
                    logsDao.insertLog(logData);
                    noticeService.updater(launchParams.actionLogId,'log',logData);
                }
                awsCF.getStack(stackData.StackId, function (err, stack) {
                    if (err) {
                        logger.error("Unable to get stack details", err);
                        return callback({"message": "Error occured while fetching stack status"});
                    }
                    if (stack) {
                        var topicARN = null;
                        var autoScaleUsername = null;
                        var autoScaleRunlist;
                        var templateObj = JSON.parse(fileData);
                        var templateResources = templateObj.Resources;
                        var templateResourcesKeys = Object.keys(templateResources);
                        for (var j = 0; j < templateResourcesKeys.length; j++) {
                            var resource = templateResources[templateResourcesKeys[j]];
                            if (resource && resource.Type === 'AWS::AutoScaling::AutoScalingGroup') {
                                var autoScaleProperties = resource.Properties;
                                if (autoScaleProperties && autoScaleProperties.NotificationConfigurations && autoScaleProperties.NotificationConfigurations.length) {
                                    for (var i = 0; i < autoScaleProperties.NotificationConfigurations.length; i++) {
                                        if (autoScaleProperties.NotificationConfigurations[i].TopicARN) {
                                            topicARN = autoScaleProperties.NotificationConfigurations[i].TopicARN;
                                            for (var count = 0; count < self.instances.length; count++) {
                                                if ('AutoScaleInstanceResource' === self.instances[count].logicalId) {
                                                    autoScaleUsername = self.instances[count].username;
                                                    autoScaleRunlist = self.instances[count].runlist;
                                                    break;
                                                }
                                            }
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        CloudFormation.createNew({
                            orgId: launchParams.orgId,
                            bgId: launchParams.bgId,
                            projectId: launchParams.projectId,
                            envId: launchParams.envId,
                            stackParameters: self.stackParameters,
                            templateFile: self.templateFile,
                            cloudProviderId: self.cloudProviderId,
                            infraManagerId: self.infraManagerId,
                            infraManagerType: self.infraMangerType,
                            stackName: launchParams.stackName,
                            stackId: stackData.StackId,
                            status: stack.StackStatus,
                            users: launchParams.users,
                            region: self.region,
                            instanceUsername: self.instanceUsername,
                            autoScaleTopicArn: topicARN,
                            autoScaleUsername: autoScaleUsername,
                            autoScaleRunlist: autoScaleRunlist
                        }, function (err, cloudFormation) {
                            if (err) {
                                logger.error("Unable to save CloudFormation data in DB", err);
                                return callback(err, null);
                            }
                            callback(null, {
                                stackId: cloudFormation._id,
                            });
                            awsCF.waitForStackCompleteStatus(stackData.StackId, function (err, completeStack) {
                                if (err) {
                                        logger.error('Unable to wait for stack status', err);
                                        if (err.stackStatus) {
                                            cloudFormation.status = err.stackStatus;
                                            cloudFormation.save();
                                        }
                                        return;
                                }
                                cloudFormation.status = completeStack.StackStatus;
                                cloudFormation.save();
                                awsCF.listAllStackResources(stackData.StackId, function (err, resources) {
                                    if (err) {
                                        logger.error('Unable to fetch stack resources', err);
                                        return;
                                    }
                                    var keyPairName;
                                    var parameters = cloudFormation.stackParameters;
                                    for (var i = 0; i < parameters.length; i++) {
                                        if (parameters[i].ParameterKey === 'KeyName') {
                                            keyPairName = parameters[i].ParameterValue;
                                            break;
                                        }
                                    }
                                    var ec2 = new EC2(awsSettings);
                                    var ec2Resources = {};
                                    var autoScaleResourceIds = [];
                                    var autoScaleResourceId = 'temp-Id';
                                    for (var i = 0; i < resources.length; i++) {
                                        if (resources[i].ResourceType === 'AWS::EC2::Instance') {
                                            ec2Resources[resources[i].PhysicalResourceId] = resources[i].LogicalResourceId;
                                            } else if (resources[i].ResourceType === 'AWS::AutoScaling::AutoScalingGroup') {
                                                autoScaleResourceId = resources[i].PhysicalResourceId;
                                                autoScaleResourceIds.push(resources[i].PhysicalResourceId);
                                            }
                                        }
                                        if (autoScaleResourceIds.length) {
                                            cloudFormation.autoScaleResourceIds = autoScaleResourceIds;
                                            cloudFormation.save();
                                        }
                                        AwsAutoScaleInstance.findByAutoScaleResourceId(autoScaleResourceId, function (err, autoScaleInstances) {
                                            if (err) {
                                                logger.error('Unable to fetch autoscale instance resources', err);
                                                return;
                                            }
                                            for (var i = 0; i < autoScaleInstances.length; i++) {
                                                ec2Resources[autoScaleInstances[i].awsInstanceId] = 'autoScaleAwsInstance';
                                            }
                                            var instanceIds = Object.keys(ec2Resources);
                                            if (instanceIds.length) {
                                                var instances = [];
                                                ec2.describeInstances(instanceIds, function (err, awsRes) {
                                                    if (err) {
                                                        logger.error("Unable to get instance details from aws", err);
                                                        return;
                                                    }
                                                    if (!(awsRes.Reservations && awsRes.Reservations.length)) {
                                                        return;
                                                    }
                                                    var reservations = awsRes.Reservations;
                                                    for (var k = 0; k < reservations.length; k++) {
                                                        if (reservations[k].Instances && reservations[k].Instances.length) {
                                                            instances = instances.concat(reservations[k].Instances);
                                                        }
                                                    }
                                                    for (var i = 0; i < instances.length; i++) {
                                                        addAndBootstrapInstance(instances[i]);
                                                    }
                                                });
                                                function addAndBootstrapInstance(instanceData) {
                                                    var keyPairName = instanceData.KeyName;
                                                    AWSKeyPair.getAWSKeyPairByProviderIdAndKeyPairName(cloudFormation.cloudProviderId, keyPairName, function (err, keyPairs) {
                                                        if (err) {
                                                            logger.error("Unable to get keypairs", err);
                                                            return;
                                                        }
                                                        if (keyPairs && keyPairs.length) {
                                                            var keyPair = keyPairs[0];
                                                            var encryptedPemFileLocation = appConfig.instancePemFilesDir + keyPair._id;
                                                            if (!launchParams.appUrls) {
                                                                launchParams.appUrls = [];
                                                            }
                                                            var appUrls = launchParams.appUrls;
                                                            if (appConfig.appUrls && appConfig.appUrls.length) {
                                                                appUrls = appUrls.concat(appConfig.appUrls);
                                                            }
                                                            var os = instanceData.Platform;
                                                            if (os) {
                                                                os = 'windows';
                                                            } else {
                                                                os = 'linux';
                                                            }
                                                            var instanceName;
                                                            var runlist = [];
                                                            var instanceUsername;
                                                            var logicalId = ec2Resources[instanceData.InstanceId];
                                                            if (logicalId === 'autoScaleAwsInstance') {
                                                                runlist = cloudFormation.autoScaleRunlist || [];
                                                                instanceUsername = cloudFormation.autoScaleUsername || 'ubuntu';
                                                                instanceName = cloudFormation.stackName + '-AutoScale';
                                                            } else {
                                                                for (var count = 0; count < self.instances.length; count++) {
                                                                    if (logicalId === self.instances[count].logicalId) {
                                                                        instanceUsername = self.instances[count].username;
                                                                        runlist = self.instances[count].runlist;
                                                                        break;
                                                                    }
                                                                }
                                                                instanceName = launchParams.blueprintName;
                                                            }
                                                            if (instanceData.Tags && instanceData.Tags.length) {
                                                                for (var j = 0; j < instanceData.Tags.length; j++) {
                                                                    if (instanceData.Tags[j].Key === 'Name') {
                                                                        instanceName = instanceData.Tags[j].Value;
                                                                    }
                                                                }
                                                            }
                                                            if (!instanceUsername) {
                                                                instanceUsername = 'ubuntu'; // hack for default username
                                                            }
                                                            var instanceSize;
                                                            for (var i = 0; i < self.stackParameters.length; i++) {
                                                                if (self.stackParameters[i].ParameterKey == "InstanceType") {
                                                                    instanceSize = self.stackParameters[i].ParameterValue;
                                                                }
                                                            }
                                                            logger.debug("instanceSize: ", instanceSize);
                                                            var instanceObj = {
                                                                name: instanceName,
                                                                masterDetails: {
                                                                    orgId: launchParams.orgId,
                                                                    orgName: launchParams.orgName,
                                                                    bgId: launchParams.bgId,
                                                                    bgName: launchParams.bgName,
                                                                    projectId: launchParams.projectId,
                                                                    projectName: launchParams.projectName,
                                                                    envId: launchParams.envId,
                                                                    environmentName: launchParams.envName
                                                                },
                                                                providerDetails: {
                                                                    id: cloudFormation.cloudProviderId,
                                                                    type: self.cloudProviderType || 'aws',
                                                                    keyPairId: keyPair._id,
                                                                    region: self.region,
                                                                    keyPairName: instanceData.KeyName,
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
                                                                    privateIp: instanceData.PrivateIpAddress || null,
                                                                    type: instanceData.InstanceType,
                                                                    launchTime: Date.parse(instanceData.LaunchTime),
                                                                    bootStrapState:'bootStrapping'
                                                                },
                                                                credentials: {
                                                                    username: instanceUsername,
                                                                    pemFileLocation: encryptedPemFileLocation
                                                                },
                                                                configDetails: {
                                                                    id: self.infraManagerId,
                                                                    nodeName: instanceData.InstanceId,
                                                                    run_list:runlist
                                                                },
                                                                blueprintDetails: {
                                                                    id: launchParams.blueprintData.id ? launchParams.blueprintData.blueprintId : null,
                                                                    name: launchParams.blueprintData.blueprintName ? launchParams.blueprintData.blueprintName : null,
                                                                    templateName: launchParams.blueprintData.templateId ? launchParams.blueprintData.templateId : null,
                                                                    templateType: launchParams.blueprintData.templateType ? launchParams.blueprintData.templateType : null
                                                                },
                                                                user:launchParams.sessionUser,
                                                                resourceType: 'EC2',
                                                                category: "managed",
                                                                authentication: 'success',
                                                                stackName: launchParams.domainName && launchParams.domainName !== null ? launchParams.domainName : launchParams.stackName,
                                                                tagServer: launchParams.tagServer,
                                                                monitor: launchParams.monitor,
                                                                cloudFormationId: cloudFormation._id
                                                            }
                                                            instanceObj.createdOn = new Date().getTime();
                                                            var queryObj = {
                                                                'masterDetails.orgId': instanceObj.masterDetails.orgId,
                                                                'providerDetails.id': cloudFormation.cloudProviderId,
                                                                'resourceDetails.platformId': instanceObj.resourceDetails.platformId
                                                            };
                                                            resourceModel.getResources(queryObj,function(err,resourceDetails){
                                                                if(err){
                                                                    logger.error("Error in fetching resource Details:",err);
                                                                }
                                                                if(resourceDetails.length > 0){
                                                                    resourceModel.updateResourceById(resourceDetails[0]._id,instanceObj, function (err, resource){
                                                                        if (err) {
                                                                            logger.error("Error in updating Resources>>>>:", err);
                                                                        }
                                                                        createInstance(resourceDetails[0]._id);
                                                                    })
                                                                }else{
                                                                    resourceModel.createNew(instanceObj, function (err, resource){
                                                                        if (err) {
                                                                            logger.error("Error in creating Resources>>>>:", err);
                                                                        }
                                                                        createInstance(resource._id);
                                                                    })
                                                                }
                                                            });
                                                            function createInstance(resourceId) {
                                                                var actionId = uuid.v4();
                                                                if (launchParams.serviceMapObj && launchParams.serviceMapObj !== null) {
                                                                    var serviceObj = launchParams.serviceMapObj;
                                                                    ymlText.aws.groups.push({
                                                                        name: instanceName,
                                                                        identifiers: {
                                                                            ip: [instanceData.PrivateIpAddress],
                                                                            subnet: [instanceData.SubnetId],
                                                                            vpc: [instanceData.VpcId]
                                                                        }
                                                                    });
                                                                    if (ymlText.aws.groups.length === instances.length) {
                                                                        var fileUpload = require('_pr/model/file-upload/file-upload');
                                                                        var async = require('async');
                                                                        var yml = require('json2yaml');
                                                                        var ymlFolderName = appConfig.tempDir;
                                                                        var ymlFileName = resourceId + '.yaml';
                                                                        var ymlFolder = path.normalize(ymlFolderName);
                                                                        mkdirp.sync(ymlFolder);
                                                                        ymlText = yml.stringify(ymlText);
                                                                        async.waterfall([
                                                                            function (next) {
                                                                                fileIo.writeFile(ymlFolder + '/' + ymlFileName, ymlText, null, next);
                                                                            },
                                                                            function (next) {
                                                                                fileUpload.uploadFile(resourceId + '.yaml', ymlFolder + '/' + ymlFileName, null, next);
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
                                                                }
                                                                var logData = {
                                                                    instanceId: resourceId,
                                                                    instanceRefId: actionId,
                                                                    botId: launchParams.botId,
                                                                    botRefId: launchParams.actionLogId,
                                                                    err: false,
                                                                    log: "Waiting for instance " + instanceName + " ok state",
                                                                    timestamp: new Date().getTime()
                                                                };
                                                                logsDao.insertLog(logData);
                                                                noticeService.updater(launchParams.actionLogId, 'log', logData);
                                                                nodeIdWithActionLogId.push({
                                                                    nodeId: resourceId,
                                                                    actionLogId: actionId
                                                                });

                                                                if (launchParams.auditTrailId !== null) {
                                                                    var resultTaskExecution = {
                                                                        "actionLogId": launchParams.actionLogId,
                                                                        "auditTrailConfig.nodeIdsWithActionLog": nodeIdWithActionLogId,
                                                                        "auditTrailConfig.nodeIds": [resourceId],
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
                                                                ec2.waitForEvent(instanceData.InstanceId, 'instanceStatusOk', function (err) {
                                                                    if (err) {
                                                                        resourceModel.updateResourceById(resourceId, {'resourceDetails.bootStrapState': 'failed'}, function (err, data) {
                                                                            if (err) {
                                                                                logger.error("Error in updating Resource Details:", err);
                                                                            }
                                                                        })
                                                                        var timestampEnded = new Date().getTime();
                                                                        var logData = {
                                                                            instanceId: resourceId,
                                                                            instanceRefId: actionId,
                                                                            botId: launchParams.botId,
                                                                            botRefId: launchParams.actionLogId,
                                                                            err: true,
                                                                            log: "Bootstrap failed",
                                                                            timestamp: timestampEnded
                                                                        };
                                                                        logsDao.insertLog(logData);
                                                                        noticeService.updater(launchParams.actionLogId, 'log', logData);
                                                                        noticeService.notice(launchParams.sessionUser, {
                                                                            title: "Blueprint BOTs Execution",
                                                                            body: "Bootstrap failed"
                                                                        }, "error", function (err, data) {
                                                                            if (err) {
                                                                                logger.error("Error in Notification Service, ", err);
                                                                            }
                                                                        });
                                                                        if (nodeIdWithActionLogId.length === instances.length && launchParams.auditTrailId !== null) {
                                                                            var resultTaskExecution = {
                                                                                "actionLogId": launchParams.actionLogId,
                                                                                "auditTrailConfig.nodeIdsWithActionLog": nodeIdWithActionLogId,
                                                                                "auditTrailConfig.nodeIds": [resourceId],
                                                                                "masterDetails.orgName": launchParams.orgName,
                                                                                "masterDetails.bgName": launchParams.bgName,
                                                                                "masterDetails.projectName": launchParams.projectName,
                                                                                "masterDetails.envName": launchParams.envName,
                                                                                "actionStatus": "failed",
                                                                                "status": "failed",
                                                                                "endedOn": new Date().getTime()
                                                                            }
                                                                            auditTrailService.updateAuditTrail(launchParams.auditType, launchParams.auditTrailId, resultTaskExecution, function (err, auditTrail) {
                                                                                if (err) {
                                                                                    logger.error("Failed to create or update bots Log: ", err);
                                                                                }
                                                                                if (launchParams.bot_id !== null) {
                                                                                    var logData = {
                                                                                        instanceId: resourceId,
                                                                                        instanceRefId: actionId,
                                                                                        botId: launchParams.botId,
                                                                                        botRefId: launchParams.actionLogId,
                                                                                        err: true,
                                                                                        log: 'BOT execution is failed for Blueprint BOT:' + launchParams.bot_id,
                                                                                        timestamp: new Date().getTime()
                                                                                    };
                                                                                    logsDao.insertLog(logData);
                                                                                    noticeService.updater(launchParams.actionLogId, 'log', logData);
                                                                                }
                                                                            });
                                                                        }
                                                                        return;
                                                                    } else {
                                                                        var resourceDetails = {
                                                                            id: resourceId,
                                                                            actionId: actionId,
                                                                            botId: launchParams.botId ? launchParams.botId : null,
                                                                            botRefId: launchParams.actionLogId ? launchParams.actionLogId : null
                                                                        }
                                                                        commonService.bootStrappingResource(resourceDetails._id, function (err, data) {
                                                                            if (err) {
                                                                                logger.error(err);
                                                                                if (nodeIdWithActionLogId.length === instances.length && launchParams.auditTrailId !== null) {
                                                                                    var resultTaskExecution = {
                                                                                        "actionLogId": launchParams.actionLogId,
                                                                                        "auditTrailConfig.nodeIdsWithActionLog": nodeIdWithActionLogId,
                                                                                        "auditTrailConfig.nodeIds": [resourceId],
                                                                                        "masterDetails.orgName": launchParams.orgName,
                                                                                        "masterDetails.bgName": launchParams.bgName,
                                                                                        "masterDetails.projectName": launchParams.projectName,
                                                                                        "masterDetails.envName": launchParams.envName,
                                                                                        "actionStatus": "failed",
                                                                                        "status": "failed",
                                                                                        "endedOn": new Date().getTime()
                                                                                    }
                                                                                    auditTrailService.updateAuditTrail(launchParams.auditType, launchParams.auditTrailId, resultTaskExecution, function (err, auditTrail) {
                                                                                        if (err) {
                                                                                            logger.error("Failed to create or update bots Log: ", err);
                                                                                        }
                                                                                        if (launchParams.bot_id !== null) {
                                                                                            var logData = {
                                                                                                instanceId: resourceId,
                                                                                                instanceRefId: actionId,
                                                                                                botId: launchParams.botId,
                                                                                                botRefId: launchParams.actionLogId,
                                                                                                err: true,
                                                                                                log: 'BOT execution is failed for Blueprint BOT:' + launchParams.bot_id,
                                                                                                timestamp: new Date().getTime()
                                                                                            };
                                                                                            logsDao.insertLog(logData);
                                                                                            noticeService.updater(launchParams.actionLogId, 'log', logData);
                                                                                        }
                                                                                    });
                                                                                }
                                                                            } else {
                                                                                if (nodeIdWithActionLogId.length === instances.length && launchParams.auditTrailId !== null) {
                                                                                    var resultTaskExecution = {
                                                                                        "actionLogId": launchParams.actionLogId,
                                                                                        "auditTrailConfig.nodeIdsWithActionLog": nodeIdWithActionLogId,
                                                                                        "auditTrailConfig.nodeIds": [resourceId],
                                                                                        "masterDetails.orgName": launchParams.orgName,
                                                                                        "masterDetails.bgName": launchParams.bgName,
                                                                                        "masterDetails.projectName": launchParams.projectName,
                                                                                        "masterDetails.envName": launchParams.envName,
                                                                                        "actionStatus": "success",
                                                                                        "status": "success",
                                                                                        "endedOn": new Date().getTime()
                                                                                    }
                                                                                    auditTrailService.updateAuditTrail(launchParams.auditType, launchParams.auditTrailId, resultTaskExecution, function (err, auditTrail) {
                                                                                        if (err) {
                                                                                            logger.error("Failed to create or update bots Log: ", err);
                                                                                        }
                                                                                        if (launchParams.bot_id !== null) {
                                                                                            var logData = {
                                                                                                instanceId: resourceId,
                                                                                                instanceRefId: actionId,
                                                                                                botId: launchParams.botId,
                                                                                                botRefId: launchParams.actionLogId,
                                                                                                err: true,
                                                                                                log: 'BOT execution is failed for Blueprint BOT:' + launchParams.bot_id,
                                                                                                timestamp: new Date().getTime()
                                                                                            };
                                                                                            logsDao.insertLog(logData);
                                                                                            noticeService.updater(launchParams.actionLogId, 'log', logData);
                                                                                        }
                                                                                    });
                                                                                }
                                                                            }
                                                                        })
                                                                    }
                                                                })
                                                            }
                                                        } else {
                                                            logger.error('keypair with name : ' + keyPairName + ' not found');
                                                        }
                                                    });
                                                }
                                            }
                                        });
                                    });
                                });
                        });
                    } else {
                        callback({
                            "message": "Error occured while fetching stack status"
                        });
                        return;
                    }
                });
            });
        });
    });

};

CloudFormationBlueprintSchema.methods.getVersionData = function (ver) {
    return null;
};

CloudFormationBlueprintSchema.methods.getLatestVersion = function () {
    return null;
};

CloudFormationBlueprintSchema.methods.getCloudProviderData = function () {
    return {
        cloudProviderId: this.cloudProviderId
    };
}

CloudFormationBlueprintSchema.methods.getInfraManagerData = function () {
    return {
        infraMangerType: this.infraManagerType,
        infraManagerId: this.infraManagerId
    };
};

CloudFormationBlueprintSchema.statics.createNew = function (data) {
    var infraManagerType;
    if (data.infraManagerType === INFRA_MANAGER_TYPE.CHEF) {
        infraManagerType = INFRA_MANAGER_TYPE.CHEF;
    } else if (data.infraManagerType === INFRA_MANAGER_TYPE.PUPPET) {
        infraManagerType = INFRA_MANAGER_TYPE.PUPPET;
        return null;
    }
    var stackParameters = [];
    if (data.stackParameters) {
        for (var i = 0; i < data.stackParameters.length; i++) {
            var parameterObj = {
                ParameterKey: data.stackParameters[i].ParameterKey
            };
            if (data.stackParameters[i].type === 'Number') {
                parameterObj.ParameterValue = parseFloat(data.stackParameters[i].ParameterValue);
            } else {
                parameterObj.ParameterValue = data.stackParameters[i].ParameterValue;
            }
            stackParameters.push(parameterObj);
        }
    }
    var self = this;
    var cftBlueprint = new self({
        cloudProviderId: data.cloudProviderId,
        infraMangerType: infraManagerType,
        infraManagerId: data.infraManagerId,
        stackParameters: stackParameters,
        templateFile: data.templateFile,
        region: data.region,
        instances: data.instances
       });
    return cftBlueprint;
};

var CloudFormationBlueprint = mongoose.model('CloudFormationBlueprint', CloudFormationBlueprintSchema);
module.exports = CloudFormationBlueprint;