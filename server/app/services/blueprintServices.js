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
var blueprintModel = require('_pr/model/blueprint/blueprint.js');
var compositeBlueprintModel = require('_pr/model/composite-blueprints/composite-blueprints.js');
var usersDao = require('_pr/model/users.js');
var ObjectId = require('mongoose').Types.ObjectId;
var async = require('async');
var uuid = require('node-uuid');
var Chef = require('_pr/lib/chef.js');
var apiUtil = require('_pr/lib/utils/apiUtil.js');
var masterUtil = require('_pr/lib/utils/masterUtil.js');
var nexus = require('_pr/lib/nexus.js');
var AppData = require('_pr/model/app-deploy/app-data');
var utils = require('_pr/model/classes/utils/utils.js');
var AWSKeyPair = require('_pr/model/classes/masters/cloudprovider/keyPair.js');
var VMImage = require('_pr/model/classes/masters/vmImage.js');
var AWSProvider = require('_pr/model/classes/masters/cloudprovider/awsCloudProvider.js');
var instanceModel = require('_pr/model/classes/instance/instance');
var AzureProvider = require('_pr/model/classes/masters/cloudprovider/azureCloudProvider.js');
var VmWareProvider = require('_pr/model/classes/masters/cloudprovider/vmwareCloudProvider.js');
var appConfig = require('_pr/config');
var Cryptography = require('_pr/lib/utils/cryptography');
var EC2 = require('_pr/lib/ec2.js');
var OpenStackProvider = require('_pr/model/classes/masters/cloudprovider/openstackCloudProvider.js');
var Docker = require('_pr/model/docker.js');
var instanceLogModel = require('_pr/model/log-trail/instanceLog.js');
var SSHExec = require('_pr/lib/utils/sshexec');
var logsDao = require('_pr/model/dao/logsdao.js');
var credentialCryptography = require('_pr/lib/credentialcryptography');
var fileIo = require('_pr/lib/utils/fileio');
var configmgmtDao = require('_pr/model/d4dmasters/configmgmt');
const errorType = 'blueprint';

var blueprintServices = module.exports = {};

blueprintServices.createNew = function createNew(blueprintData,userDetails,callback){
    async.waterfall([
        function(next){
            usersDao.haspermission(userDetails.userName, userDetails.category, userDetails.action, userDetails.req, userDetails.permissionSet,next);
        },
        function(permissionStatus,next){
            if(permissionStatus){
                if(blueprintData.domainNameCheck && blueprintData.domainNameCheck === 'true'){
                    blueprintData.domainNameCheck = true;
                }
                blueprintModel.createNew(blueprintData, next);
            }else{
                next({
                    errCode:401,
                    errMessage:'No permission to ' + userDetails.action + ' on ' + userDetails.category
                },null)
            }
        }
    ],function(err,results){
        if(err){
            callback(err,null);
            return;
        }
        callback(null,results);
        return;
    })
}

blueprintServices.updateBlueprint = function updateBlueprint(blueprintId,blueprintData,callback){
    async.waterfall([
        function(next){
            blueprintModel.getBlueprintById(blueprintId,next);
        },
        function(blueprints,next){
            if(blueprints.length > 0){
                if(blueprintData.domainNameCheck && blueprintData.domainNameCheck === 'true'){
                    blueprintData.domainNameCheck = true;
                }
                blueprintModel.update(blueprintData, next);
            }else{
                next({
                    errCode:400,
                    errMessage:'There is no blueprint present corresponding to ' + blueprintId + ' in catalyst'
                },null)
            }
        }
    ],function(err,results){
        if(err){
            callback(err,null);
            return;
        }
        callback(null,results);
        return;
    })
}

blueprintServices.getBlueprintById = function getBlueprintById(blueprintId,callback){
    async.waterfall([
        function(next){
            blueprintModel.getBlueprintById(blueprintId,next);
        },
        function(blueprints,next){
            if(blueprints.length > 0){
                 next(null,blueprints[0]);
            }else{
                next({
                    errCode:400,
                    errMessage:'There is no blueprint present corresponding to ' + blueprintId + ' in catalyst'
                },null)
            }
        }
    ],function(err,results){
        if(err){
            callback(err,null);
            return;
        }
        callback(null,results);
        return;
    })
}


blueprintServices.removeBlueprintById = function removeBlueprintById(blueprintId,callback){
    async.waterfall([
        function(next){
            blueprintModel.getBlueprintById(blueprintId,next);
        },
        function(blueprints,next){
            if(blueprints.length > 0){
                blueprintModel.removeById(blueprintId,next);
            }else{
                next({
                    errCode:400,
                    errMessage:'There is no blueprint present corresponding to ' + blueprintId + ' in catalyst'
                },null)
            }
        }
    ],function(err,results){
        if(err){
            callback(err,null);
            return;
        }
        callback(null,results);
        return;
    })
}

blueprintServices.copyBlueprint = function copyBlueprint(blueprintIds,masterDetails,callback){
    async.waterfall([
        function(next){
            blueprintModel.getBlueprintByIds(blueprintIds,next);
        },
        function(blueprints,next){
            if(blueprints.length > 0){
                var count = 0;
                for(var i = 0; i < blueprints.length.length; i++){
                    (function(blueprint){
                        blueprint.masterDetails = masterDetails;
                        blueprint.parentId = undefined;
                        if (blueprint.masterDetails.projectId !== masterDetails.projectId) {
                            if (blueprint.serverDetails) {
                                blueprint.serverDetails = undefined;
                            }
                        }
                        blueprint._id = new ObjectId();
                        blueprint.blueprintName = blueprint.blueprintName + '_copy_' + uuid.v4().split('-')[0];
                        blueprintModel.createNew(blueprint, function(err,data){
                            if(err){
                                next(err,null);
                                return;
                            }else{
                                count++;
                                if(count === blueprints.length){
                                    next(null,data);
                                }
                            }
                        });
                    })(blueprints[i])
                }
            }else{
                next({
                    errCode:400,
                    errMessage:'There is no blueprint present corresponding to ' + blueprintIds + ' in catalyst'
                },null)
            }
        }
    ],function(err,results){
        if(err){
            callback(err,null);
            return;
        }
        callback(null,results);
        return;
    })
}

blueprintServices.getBlueprintByOrgBgProject = function getBlueprintByOrgBgProject(queryObj,callback){
    if(typeof queryObj.queryParam !== 'undefined' && queryObj.queryParam !== null && queryObj.queryParam !== '') {
        var reqData = {};
        async.waterfall([
            function (next) {
                apiUtil.paginationRequest(queryObj.queryParam, 'blueprints', next);
            },
            function (paginationReq, next) {
                if (queryObj.queryParam.templateType === 'composite') {
                    paginationReq['organizationId'] = queryObj.queryParam.orgId;
                    paginationReq['businessGroupId'] = queryObj.queryParam.bgId;
                    paginationReq['projectId'] = queryObj.queryParam.projectId;
                    paginationReq['cloudProviderType'] = queryObj.queryParam.providerType;
                    paginationReq['searchColumns'] = ['blueprintName'];
                } else {
                    paginationReq['masterDetails.orgId'] = queryObj.queryParam.orgId;
                    paginationReq['masterDetails.bgId'] = queryObj.queryParam.bgId;
                    paginationReq['masterDetails.projectId'] = queryObj.queryParam.projectId;
                    paginationReq['templateDetails.type'] = queryObj.queryParam.templateType;
                    paginationReq['providerDetails.type'] = queryObj.queryParam.providerType;
                    paginationReq['searchColumns'] = ['blueprintName'];
                }
                reqData = paginationReq;
                apiUtil.databaseUtil(paginationReq, next);
            },
            function (query, next) {
                if (queryObj.queryParam.templateType === 'composite') {
                    compositeBlueprintModel.getCompositeBlueprintByOrgBgProject(query, next)
                } else {
                    blueprintModel.getBlueprintByOrgBgProjectProviderType(query, next);
                }
            },
            function (blueprints, next) {
                if (queryObj.queryParam.pagination === 'true') {
                    apiUtil.paginationResponse(blueprints, reqData, next);
                } else {
                    next(null, blueprints.docs);
                }
            }], function (err, results) {
            if (err) {
                callback({
                    "errorCode": 500,
                    "message": "Error occured while fetching Blueprints."
                },null);
                return;
            } else {
                return callback(null,results);
            }
        });
    }else {
        var jsonData = {};
        jsonData['masterDetails.orgId'] = queryObj.queryParam.orgId;
        jsonData['masterDetails.bgId'] = queryObj.queryParam.bgId;
        jsonData['masterDetails.projectId'] = queryObj.queryParam.projectId;
        blueprintModel.getBlueprintByOrgBgProject(jsonData, function (err, data) {
            if (err) {
                callback(err, null);
                return;
            }
            return callback(null, data);
        });
    }
}



blueprintServices.launchBlueprint = function launchBlueprint(blueprintId,userDetails,queryParam, callback) {
    async.waterfall([
        function(next){
            usersDao.haspermission(userDetails.userName, userDetails.category, userDetails.action, userDetails.req, userDetails.permissionSet,next);
        },
        function(permissionStatus,next){
            if(permissionStatus){
                blueprintModel.getBlueprintById(blueprintId,next);
            }else{
                next({
                    errCode:401,
                    errMessage:'No permission to ' + userDetails.action + ' on ' + userDetails.category
                },null)
            }
        },
        function(blueprints,next){
            if(blueprints.length > 0){
                var stackName = null, domainName = null;
                if (blueprints[0].blueprintType === 'aws_cf' || blueprints[0].blueprintType === 'azure_arm') {
                    stackName = queryParam.stackName;
                    if (!stackName) {
                        next({
                            errCode:400,
                            errMessage:'Invalid Stack Name'
                        },null)
                    }
                }
                if(blueprints[0].domainNameCheck === true) {
                    domainName = queryParam.domainName;
                    if (!domainName) {
                        next({
                            errCode:400,
                            errMessage:'Invalid Domain Name'
                        },null)
                    }
                }
                var blueprintLaunchParams ={
                    envId: queryParam.envId,
                    ver: queryParam.version,
                    stackName: stackName,
                    domainName:domainName,
                    sessionUser: queryParam.userName
                }
                next(null,blueprints[0],blueprintLaunchParams);
            }else{
                next({
                    errCode:404,
                    errMessage:'Blueprint Does Not Exist'
                },null);
            }

        },
        function(blueprintData,launchParams,next){
            configmgmtDao.getEnvNameFromEnvId(launchParams.envId, function(err, envName) {
                if (err) {
                      next(err);
                };
                configmgmtDao.getChefServerDetails(blueprintData.infraManagerDetails.id, function(err, chefDetails) {
                        if (err) {
                          next(err);
                        };
                        var chef = new Chef({
                            userChefRepoLocation: chefDetails.chefRepoLocation,
                            chefUserName: chefDetails.loginname,
                            chefUserPemFile: chefDetails.userpemfile,
                            chefValidationPemFile: chefDetails.validatorpemfile,
                            hostedChefUrl: chefDetails.url
                        });
                        var blueprintConfigType = getBlueprintConfigType(self);
                        if (!blueprintData.appUrls) {
                            blueprintData.appUrls = [];
                        }
                        var appUrls = blueprintData.appUrls;
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
        }
    ],function(err,results){
        if(err){
            callback(err,null);
        }
        callback(null,results);
    })
};

function getCookBookAttributes(blueprintData,instance,serverData,callback){
    var objectArray = [];
    if (blueprintData.blueprintConfig.infraManagerDetails.infraManagerData
        && blueprint.blueprintConfig.infraManagerDetails.infraManagerData.versionsList
        && blueprint.blueprintConfig.infraManagerDetails.infraManagerData.versionsList.length) {
        var attributes = blueprint.blueprintConfig.infraManagerDetails.infraManagerData.versionsList[0].attributes;
        if (attributes && attributes.length) {
            for (var i = 0; i < attributes.length; i++) {
                objectArray.push(attributes[i].jsonObj);
            }
        }
    }
    if (blueprintData.serverDetails.serverType === 'nexus' && blueprintData.serverDetails.serverConfiguration.url) {
        masterUtil.updateProject(serverData.projectId, serverData.repoName, function(err, data) {
            if (err) {
                logger.debug("Failed to updateProject: ", err);
            }
            if (data) {
                logger.debug("updateProject successful.");
            }
        });
        var url = blueprintData.serverDetails.serverConfiguration.url;
        var repoName = blueprintData.serverDetails.serverConfiguration.repoName;
        var groupId = blueprintData.serverDetails.serverConfiguration.groupId.replace(/\./g, '/');
        var artifactId = blueprintData.serverDetails.serverConfiguration.artifactId;
        var version = blueprintData.serverDetails.serverConfiguration.version;
        objectArray.push({
            "rlcatalyst": {
                "upgrade": false
            }
        });
        objectArray.push({
            "rlcatalyst": {
                "applicationNodeIP": instance.instanceIP
            }
        });
        nexus.getNexusArtifactVersions(blueprintData.serverDetails.repoId, repoName, groupId, artifactId, function(err, data) {
            if (err) {
                logger.debug("Failed to fetch Repository from Mongo: ", err);
                objectArray.push({
                    "rlcatalyst": {
                        "nexusUrl": url
                    }
                });
                objectArray.push({
                    "rlcatalyst": {
                        "version": version
                    }
                });
            }
            if (data) {
                var flag = false;
                var versions = data.metadata.versioning[0].versions[0].version;
                var latestVersionIndex = versions.length;
                var latestVersion = versions[latestVersionIndex - 1];
                nexus.getNexusArtifact(blueprintData.serverDetails.repoId, repoName, groupId, function(err, artifacts) {
                    if (err) {
                        logger.debug("Failed to get artifacts.");
                        objectArray.push({
                            "rlcatalyst": {
                                "nexusUrl": url
                            }
                        });
                        objectArray.push({
                            "rlcatalyst": {
                                "version": version
                            }
                        });
                    } else {
                        if (artifacts.length) {
                            for (var i = 0; i < artifacts.length; i++) {
                                if (latestVersion === artifacts[i].version && artifactId === artifacts[i].artifactId) {
                                    url = artifacts[i].resourceURI;
                                    objectArray.push({
                                        "rlcatalyst": {
                                            "nexusUrl": url
                                        }
                                    });
                                    objectArray.push({
                                        "rlcatalyst": {
                                            "version": latestVersion
                                        }
                                    });
                                    flag = true;
                                    break;
                                }
                            }
                            if (!flag) {
                                objectArray.push({
                                    "rlcatalyst": {
                                        "nexusUrl": url
                                    }
                                });
                                objectArray.push({
                                    "rlcatalyst": {
                                        "version": version
                                    }
                                });
                            }
                        } else {
                            objectArray.push({
                                "rlcatalyst": {
                                    "nexusUrl": url
                                }
                            });
                            objectArray.push({
                                "rlcatalyst": {
                                    "version": latestVersion
                                }
                            });
                        }
                    }
                    var actualVersion = "";
                    if (latestVersion) {
                        actualVersion = latestVersion;
                    } else {
                        actualVersion = version;
                    }
                    var nodeIds = [];
                    nodeIds.push(instance.id);
                        var appData = {
                            "projectId": instance.projectId,
                            "envName": instance.environmentName,
                            "appName": artifactId,
                            "version": actualVersion,
                            "nexus": {
                                "rowId": blueprintData.serverDetails.rowId,
                                "repoURL": url,
                                "artifactId": artifactId,
                                "nodeIds": nodeIds,
                                "repository": repoName,
                                "groupId": blueprintData.serverDetails.serverConfiguration.groupId,
                                "taskId": ""
                            }
                        };
                        AppData.createNewOrUpdate(appData, function(err, data) {
                            if (err) {
                                logger.debug("Failed to create or update app-data: ", err);
                            }
                            if (data) {
                                logger.debug("Created or Updated app-data successfully: ", data);
                            }
                        });
                    });
                    var attributeObj = utils.mergeObjects(objectArray);
                    callback(null, attributeObj);
                    return;
            } else {
                logger.debug("No artifact version found.");
                callback(null, data);
                return;
            }

        });
    } else if (blueprintData.serverDetails.serverType === 'docker'
        && blueprintData.serverDetails.serverConfiguration.image) {
        var containerValue = uuid.v4();
        if (blueprintData.serverDetails.serverConfiguration.containerId) {
            objectArray.push({
                "rlcatalyst": {
                    "containerId": blueprintData.serverDetails.serverConfiguration.containerId
                }
            });
        } else {
            objectArray.push({
                "rlcatalyst": {
                    "containerId": containerValue
                }
            });
        }
        if (blueprintData.serverDetails.serverConfiguration.containerPort) {
            objectArray.push({
                "rlcatalyst": {
                    "containerPort": blueprintData.serverDetails.serverConfiguration.containerPort
                }
            });
        }
        if (blueprintData.serverDetails.serverConfiguration.image) {
            objectArray.push({
                "rlcatalyst": {
                    "dockerImage": blueprintData.serverDetails.serverConfiguration.image
                }
            });
        }
        if (blueprintData.serverDetails.serverConfiguration.hostPort) {
            objectArray.push({
                "rlcatalyst": {
                    "hostPort": blueprintData.serverDetails.serverConfiguration.hostPort
                }
            });
        }
        if (blueprintData.serverDetails.serverConfiguration.dockerUser) {
            objectArray.push({
                "rlcatalyst": {
                    "dockerUser": blueprintData.serverDetails.serverConfiguration.dockerUser
                }
            });
        }
        if (blueprintData.serverDetails.serverConfiguration.dockerPassword) {
            objectArray.push({
                "rlcatalyst": {
                    "dockerPassword": blueprintData.serverDetails.serverConfiguration.dockerPassword
                }
            });
        }
        if (blueprintData.serverDetails.serverConfiguration.dockerEmailId) {
            objectArray.push({
                "rlcatalyst": {
                    "dockerEmailId": blueprintData.serverDetails.serverConfiguration.dockerEmailId
                }
            });
        }
        if (blueprintData.serverDetails.serverConfiguration.imageTag) {
            objectArray.push({
                "rlcatalyst": {
                    "imageTag": blueprintData.serverDetails.serverConfiguration.imageTag
                }
            });
        }
        objectArray.push({
            "rlcatalyst": {
                "upgrade": false
            }
        });

        objectArray.push({
            "rlcatalyst": {
                "applicationNodeIP": instance.instanceIP
            }
        });
        var attributeObj = utils.mergeObjects(objectArray);
        var nodeIds = [];
        nodeIds.push(instance.id);
        var docker = {
            "rowId": blueprintData.serverDetails.serverConfiguration.rowId,
            "image": blueprintData.serverDetails.serverConfiguration.image,
            "containerName": blueprintData.serverDetails.serverConfiguration.containerId ? lueprintData.serverDetails.serverConfiguration.containerId : containerValue,
            "containerPort": blueprintData.serverDetails.serverConfiguration.containerPort,
            "hostPort": blueprintData.serverDetails.serverConfiguration.hostPort,
            "dockerUser": blueprintData.serverDetails.serverConfiguration.dockerUser,
            "dockerPassword": blueprintData.serverDetails.serverConfiguration.dockerPassword,
            "dockerEmailId": blueprintData.serverDetails.serverConfiguration.dockerEmailId,
            "imageTag": blueprintData.serverDetails.serverConfiguration.imageTag,
            "nodeIds": nodeIds,
            "taskId": ""
        };
        var appData = {
            "projectId": instance.projectId,
            "envName": instance.environmentName,
            "appName": blueprintData.serverDetails.serverConfiguration.image,
            "version": blueprintData.serverDetails.serverConfiguration.imageTag,
            "docker": docker
        };
        AppData.createNewOrUpdate(appData, function(err, data) {
            if (err) {
                logger.debug("Failed to create or update app-data: ", err);
            }
            if (data) {
                logger.debug("Created or Updated app-data successfully: ", data);
            }
        })
        callback(null, attributeObj);
        return;
    } else {
        var attributeObj = utils.mergeObjects(objectArray);
        callback(null, attributeObj);
        return;
    }
}

function launchAWSBlueprint(launchParams,callback){
    VMImage.getImageById(blueprintData.imageDetails.id,function(err,imageData){
        if(err){
            next(err);
        }
        AWSProvider.getAWSProviderById(imageData.providerId, function(err, providerData) {
            if (err) {
                next(err);
            }
            AWSKeyPair.getAWSKeyPairById(blueprintData.keyPairDetails.id, function (err, keyPairData) {
                if (err) {
                    next(err);
                }
                var awsSettings;
                var cryptConfig = appConfig.cryptoSettings;
                var cryptography = new Cryptography(cryptConfig.algorithm,
                    cryptConfig.password);
                if (providerData.isDefault) {
                    awsSettings = {
                        "isDefault": true,
                        "region": keyPairData.region,
                        "keyPairName": keyPairData.keyPairName
                    };
                } else {
                    var decryptedAccessKey = cryptography.decryptText(providerData.accessKey,
                        cryptConfig.decryptionEncoding, cryptConfig.encryptionEncoding);
                    var decryptedSecretKey = cryptography.decryptText(providerData.secretKey,
                        cryptConfig.decryptionEncoding, cryptConfig.encryptionEncoding);

                    awsSettings = {
                        "access_key": decryptedAccessKey,
                        "secret_key": decryptedSecretKey,
                        "region": keyPairData.region,
                        "keyPairName": keyPairData.keyPairName
                    };
                }
                var encryptedPassword;
                var encryptedPemFileLocation;
                if (imageData.instancePassword && imageData.instancePassword.length) {
                    encryptedPassword = imageData.instancePassword;
                } else {
                    encryptedPemFileLocation = appConfig.instancePemFilesDir + keyPairData._id;
                }

                var securityGroupIds = [];
                for (var i = 0; i < blueprintData.securityGroupDetails.length; i++) {
                    securityGroupIds.push(blueprintData.securityGroupDetails[i].id);
                }

                var ec2 = new EC2(awsSettings);
                var paramRunList = [];
                var paramAttributes = [];
                if (launchParams && launchParams.version) {
                    paramRunList = launchParams.version.runlist;
                    paramAttributes = launchParams.version.attributes;
                }
                ec2.launchInstance(imageData.imageIdentifier, blueprintData.instanceType, securityGroupIds, blueprintData.subnetDetails.id, 'D4D-' + blueprintData.blueprintName, keyPairData.keyPairName, blueprintData.instanceCount, function(err, instanceDataAll) {
                    if (err) {
                        next(err)
                    }
                    var newInstanceIDs = [];
                    function addInstanceWrapper(instanceData, instancesLength) {
                        var instance = {
                            name: launchParams.blueprintName,
                            orgId: launchParams.orgId,
                            orgName: launchParams.orgName,
                            bgId: launchParams.bgId,
                            bgName: launchParams.bgName,
                            projectId: launchParams.projectId,
                            projectName: launchParams.projectName,
                            envId: launchParams.envId,
                            environmentName: launchParams.envName,
                            providerId: launchParams.cloudProviderId,
                            providerType: launchParams.cloudProviderType,
                            keyPairId: self.keyPairId,
                            region: aKeyPair.region,
                            chefNodeName: instanceData.InstanceId,
                            runlist: paramRunList,
                            attributes: paramAttributes,
                            platformId: instanceData.InstanceId,
                            appUrls: launchParams.appUrls,
                            instanceIP: instanceData.PublicIpAddress || null,
                            instanceState: instanceData.State.Name,
                            bootStrapStatus: 'waiting',
                            users: launchParams.users,
                            instanceType: self.instanceType,
                            catUser: launchParams.sessionUser,
                            hardware: {
                                platform: 'unknown',
                                platformVersion: 'unknown',
                                architecture: 'unknown',
                                memory: {
                                    total: 'unknown',
                                    free: 'unknown',
                                },
                                os: self.instanceOS
                            },
                            vpcId: instanceData.VpcId,
                            subnetId: instanceData.SubnetId,
                            privateIpAddress: instanceData.PrivateIpAddress,
                            hostName:instanceData.PrivateDnsName,
                            credentials: {
                                username: anImage.userName,
                                pemFileLocation: encryptedPemFileLocation,
                                password: encrptedPassword
                            },
                            chef: {
                                serverId: launchParams.infraManagerId,
                                chefNodeName: instanceData.InstanceId
                            },
                            blueprintData: {
                                blueprintId: launchParams.blueprintData.id,
                                blueprintName: launchParams.blueprintData.name,
                                templateId: launchParams.blueprintData.templateId,
                                templateType: launchParams.blueprintData.templateType,
                                templateComponents: launchParams.blueprintData.templateComponents,
                                iconPath: launchParams.blueprintData.iconpath
                            }
                        };
                        instanceModel.createInstance(instance, function(err, data) {
                            if (err) {
                                next(err);
                            }
                            instance = data;
                            instance.id = data._id;
                            newInstanceIDs.push(instance.id);
                            if (newInstanceIDs.length >= instancesLength) {
                                next(null, {
                                    "id": newInstanceIDs,
                                    "message": "instance launch success"
                                });
                            }
                            var timestampStarted = new Date().getTime();
                            var actionLog = instanceModel.insertBootstrapActionLog(instance.id, instance.runlist, launchParams.sessionUser, timestampStarted);
                            var logsReferenceIds = [instance.id, actionLog._id];
                            var instanceLog = {
                                actionId: actionLog._id,
                                instanceId: instance.id,
                                orgName: launchParams.orgName,
                                bgName: launchParams.bgName,
                                projectName: launchParams.projectName,
                                envName: launchParams.envName,
                                status: instanceData.State.Name,
                                actionStatus: "waiting",
                                platformId: instanceData.InstanceId,
                                blueprintName: launchParams.blueprintData.name,
                                data: paramRunList,
                                platform: "unknown",
                                os: self.instanceOS,
                                size: self.instanceType,
                                user: launchParams.sessionUser,
                                startedOn: new Date().getTime(),
                                createdOn: new Date().getTime(),
                                providerType: launchParams.cloudProviderType,
                                action: "Bootstrap",
                                logs: [{
                                    err: false,
                                    log: "Starting instance",
                                    timestamp: new Date().getTime()
                                }]
                            };

                            instanceLogModel.createOrUpdate(actionLog._id, instance.id, instanceLog, function(err, logData) {
                                if (err) {
                                    logger.error("Failed to create or update instanceLog: ", err);
                                }
                            });

                            logsDao.insertLog({
                                referenceId: logsReferenceIds,
                                err: false,
                                log: "Starting instance",
                                timestamp: timestampStarted
                            });
                            ec2.waitForInstanceRunnnigState(instance.platformId, function(err, instanceData) {
                                if (err) {
                                    var timestamp = new Date().getTime();
                                    instanceLog.logs = {
                                        err: true,
                                        log: "Instance ready state wait failed. Unable to bootstrap",
                                        timestamp: new Date().getTime()
                                    };
                                    instanceLog.actionStatus = "failed";
                                    instanceLog.endedOn = new Date().getTime();
                                    instanceLogModel.createOrUpdate(actionLog._id, instance.id, instanceLog, function(err, logData) {
                                        if (err) {
                                            logger.error("Failed to create or update instanceLog: ", err);
                                        }
                                    });

                                    logsDao.insertLog({
                                        referenceId: logsReferenceIds,
                                        err: true,
                                        log: "Instance ready state wait failed. Unable to bootstrap",
                                        timestamp: timestamp
                                    });
                                    logger.error("waitForInstanceRunnnigState returned an error  >>", err);
                                    return;
                                }
                                logger.debug("Enter waitForInstanceRunnnigState :", instanceData);
                                instance.instanceIP = instanceData.PublicIpAddress || instanceData.PrivateIpAddress;
                                instanceModel.updateInstanceIp(instance.id, instance.instanceIP, function(err, updateCount) {
                                    if (err) {
                                        logger.error("instancesDao.updateInstanceIp Failed ==>", err);
                                        return;
                                    }
                                    logger.debug('Instance ip upadated');
                                });
                                instanceModel.updateInstanceState(instance.id, instanceData.State.Name, function(err, updateCount) {
                                    if (err) {
                                        logger.error("error(date instance state err ==>", err);
                                        return;
                                    }
                                    logger.debug('instance state upadated');
                                });

                                instanceLog.status = instanceData.State.Name;
                                instanceLog.logs = {
                                    err: false,
                                    log: "waiting for instance state to be ok",
                                    timestamp: new Date().getTime()
                                };
                                instanceLogModel.createOrUpdate(actionLog._id, instance.id, instanceLog, function(err, logData) {
                                    if (err) {
                                        logger.error("Failed to create or update instanceLog: ", err);
                                    }
                                });

                                logger.debug('waiting for instance');
                                logsDao.insertLog({
                                    referenceId: logsReferenceIds,
                                    err: false,
                                    log: "waiting for instance state to be ok",
                                    timestamp: new Date().getTime()
                                });
                                ec2.waitForEvent(instanceData.InstanceId, 'instanceStatusOk', function(err) {
                                    if (err) {
                                        instanceLog.logs = {
                                            err: true,
                                            log: "Instance ok state wait failed. Unable to bootstrap",
                                            timestamp: new Date().getTime()
                                        };
                                        instanceLog.actionStatus = "failed";
                                        instanceLog.endedOn = new Date().getTime();
                                        instanceLogModel.createOrUpdate(actionLog._id, instance.id, instanceLog, function(err, logData) {
                                            if (err) {
                                                logger.error("Failed to create or update instanceLog: ", err);
                                            }
                                        });
                                        logsDao.insertLog({
                                            referenceId: logsReferenceIds,
                                            err: true,
                                            log: "Instance ok state wait failed. Unable to bootstrap",
                                            timestamp: new Date().getTime()
                                        });
                                        logger.error('instance wait failed ==> ', err);
                                        return;
                                    }
                                    logger.debug('instance wait success');
                                    var tempUncryptedPemFileLoc = appConfig.tempDir + uuid.v4();
                                    credentialCryptography.decryptCredential(instance.credentials, function(err, decryptedCredentials) {

                                        if (err) {
                                            instanceModel.updateInstanceBootstrapStatus(instance.id, 'failed', function(err, updateData) {
                                                if (err) {
                                                    logger.error("Unable to set instance bootstarp status", err);
                                                } else {
                                                    logger.debug("Instance bootstrap status set to failed");
                                                }
                                            });
                                            instanceLog.endedOn = new Date().getTime();
                                            instanceLog.actionStatus = "failed";
                                            instanceLog.logs = {
                                                err: true,
                                                log: "Unable to decrpt pem file. Bootstrap failed",
                                                timestamp: new Date().getTime()
                                            };
                                            instanceLogModel.createOrUpdate(actionLog._id, instance.id, instanceLog, function(err, logData) {
                                                if (err) {
                                                    logger.error("Failed to create or update instanceLog: ", err);
                                                }
                                            });

                                            var timestampEnded = new Date().getTime();
                                            logsDao.insertLog({
                                                referenceId: logsReferenceIds,
                                                err: true,
                                                log: "Unable to decrpt pem file. Bootstrap failed",
                                                timestamp: timestampEnded
                                            });
                                            instanceModel.updateActionLog(instance.id, actionLog._id, false, timestampEnded);

                                            if (instance.hardware.os != 'windows')
                                                return;
                                        }


                                        var repoData = {};
                                        repoData['projectId'] = launchParams.blueprintData.masterDetails.projectId;
                                        if (launchParams.blueprintData.serverDetails.serverType === 'nexus' && launchParams.blueprintData.serverDetails.serverConfiguration.repoName) {
                                            repoData['repoName'] = launchParams.blueprintData.serverDetails.serverConfiguration.repoName;
                                        } else if (launchParams.blueprintData.serverDetails.serverType === 'docker'  && launchParams.blueprintData.serverDetails.serverConfiguration.image) {
                                            repoData['repoName'] = launchParams.blueprintData.serverDetails.serverConfiguration.image;
                                        }
                                        getCookBookAttributes(blueprintData,instance,repoData, function(err, jsonAttributes) {
                                            var runList = instance.runlist;
                                            if (launchParams.blueprintData.extraRunlist) {
                                                runList = launchParams.blueprintData.extraRunlist.concat(instance.runlist);
                                            }
                                            var bootstrapInstanceParams = {
                                                instanceIp: instance.instanceIP,
                                                pemFilePath: decryptedCredentials.pemFileLocation,
                                                runlist: runList,
                                                instanceUsername: instance.credentials.username,
                                                nodeName: instance.chef.chefNodeName,
                                                environment: launchParams.envName,
                                                instanceOS: instance.hardware.os,
                                                jsonAttributes: jsonAttributes,
                                                instancePassword: decryptedCredentials.password
                                            };
                                            launchParams.infraManager.bootstrapInstance(bootstrapInstanceParams, function(err, code) {
                                                if (decryptedCredentials.pemFileLocation) {
                                                    fileIo.removeFile(decryptedCredentials.pemFileLocation, function(err) {
                                                        if (err) {
                                                            logger.error("Unable to delete temp pem file =>", err);
                                                        } else {
                                                            logger.debug("temp pem file deleted =>", err);
                                                        }
                                                    });
                                                }
                                                if (err) {
                                                    instanceLog.endedOn = new Date().getTime();
                                                    instanceLog.actionStatus = "failed";
                                                    instanceLog.logs = {
                                                        err: true,
                                                        log: "Bootstrap failed",
                                                        timestamp: new Date().getTime()
                                                    };
                                                    instanceLogModel.createOrUpdate(actionLog._id, instance.id, instanceLog, function(err, logData) {
                                                        if (err) {
                                                            logger.error("Failed to create or update instanceLog: ", err);
                                                        }
                                                    });
                                                    logger.error("knife launch err ==>", err);
                                                    instanceModel.updateInstanceBootstrapStatus(instance.id, 'failed', function(err, updateData) {

                                                    });
                                                    var timestampEnded = new Date().getTime();
                                                    logsDao.insertLog({
                                                        referenceId: logsReferenceIds,
                                                        err: true,
                                                        log: "Bootstrap failed",
                                                        timestamp: timestampEnded
                                                    });
                                                    instanceModel.updateActionLog(instance.id, actionLog._id, false, timestampEnded);
                                                } else {
                                                    if (code == 0) {
                                                        instanceModel.updateInstanceBootstrapStatus(instance.id, 'success', function(err, updateData) {
                                                            if (err) {
                                                                logger.error("Unable to set instance bootstarp status. code 0", err);
                                                            } else {
                                                                logger.debug("Instance bootstrap status set to success");
                                                            }
                                                        });
                                                        instanceLog.endedOn = new Date().getTime();
                                                        instanceLog.actionStatus = "success";
                                                        instanceLog.logs = {
                                                            err: false,
                                                            log: "Instance Bootstrapped successfully",
                                                            timestamp: new Date().getTime()
                                                        };
                                                        instanceLogModel.createOrUpdate(actionLog._id, instance.id, instanceLog, function(err, logData) {
                                                            if (err) {
                                                                logger.error("Failed to create or update instanceLog: ", err);
                                                            }
                                                        });
                                                        var timestampEnded = new Date().getTime();
                                                        logsDao.insertLog({
                                                            referenceId: logsReferenceIds,
                                                            err: false,
                                                            log: "Instance Bootstrapped successfully",
                                                            timestamp: timestampEnded
                                                        });
                                                        if(typeof domainName !== 'undefined' && domainName !== '' && domainName !== null && domainName !== 'null') {
                                                            resourceService.updateDomainNameForInstance(domainName, instance.instanceIP,instance.id, awsSettings, function (err, updateDomainName) {
                                                                if (err) {
                                                                    logger.error("resourceService.updateDomainNameForInstance Failed ==>", err);
                                                                    return;
                                                                }
                                                                logger.debug("Domain name is updated successfully");
                                                            });
                                                        }
                                                        instanceModel.updateActionLog(instance.id, actionLog._id, true, timestampEnded);
                                                        launchParams.infraManager.getNode(instance.chefNodeName, function(err, nodeData) {
                                                            if (err) {
                                                                logger.error("Failed chef.getNode", err);
                                                                return;
                                                            }
                                                            instanceLog.platform = nodeData.automatic.platform;
                                                            instanceLogModel.createOrUpdate(actionLog._id, instance.id, instanceLog, function(err, logData) {
                                                                if (err) {
                                                                    logger.error("Failed to create or update instanceLog: ", err);
                                                                }
                                                            });
                                                            var hardwareData = {};
                                                            hardwareData.architecture = nodeData.automatic.kernel.machine;
                                                            hardwareData.platform = nodeData.automatic.platform;
                                                            hardwareData.platformVersion = nodeData.automatic.platform_version;
                                                            hardwareData.memory = {
                                                                total: 'unknown',
                                                                free: 'unknown'
                                                            };
                                                            if (nodeData.automatic.memory) {
                                                                hardwareData.memory.total = nodeData.automatic.memory.total;
                                                                hardwareData.memory.free = nodeData.automatic.memory.free;
                                                            }
                                                            hardwareData.os = instance.hardware.os;
                                                            instanceModel.setHardwareDetails(instance.id, hardwareData, function(err, updateData) {
                                                                if (err) {
                                                                    logger.error("Unable to set instance hardware details  code (setHardwareDetails)", err);
                                                                } else {
                                                                    logger.debug("Instance hardware details set successessfully");
                                                                }
                                                            });
                                                            var _docker = new Docker();
                                                            _docker.checkDockerStatus(instance.id,
                                                                function(err, retCode) {
                                                                    if (err) {
                                                                        logger.error("Failed _docker.checkDockerStatus", err);
                                                                        next(retCode);
                                                                    }
                                                                    logger.debug('Docker Check Returned:' + retCode);
                                                                    if (retCode === '0') {
                                                                        instanceModel.updateInstanceDockerStatus(instance.id, "success", '', function(data) {
                                                                            logger.debug('Instance Docker Status set to Success');
                                                                        });

                                                                    }
                                                                });

                                                        });

                                                    } else {
                                                        instanceModel.updateInstanceBootstrapStatus(instance.id, 'failed', function(err, updateData) {
                                                            if (err) {
                                                                logger.error("Unable to set instance bootstarp status code != 0", err);
                                                            } else {
                                                                logger.debug("Instance bootstrap status set to failed");
                                                            }
                                                        });
                                                        instanceLog.endedOn = new Date().getTime();
                                                        instanceLog.actionStatus = "failed";
                                                        instanceLog.logs = {
                                                            err: false,
                                                            log: "Bootstrap Failed",
                                                            timestamp: new Date().getTime()
                                                        };
                                                        instanceLogModel.createOrUpdate(actionLog._id, instance.id, instanceLog, function(err, logData) {
                                                            if (err) {
                                                                logger.error("Failed to create or update instanceLog: ", err);
                                                            }
                                                        });
                                                        var timestampEnded = new Date().getTime();
                                                        logsDao.insertLog({
                                                            referenceId: logsReferenceIds,
                                                            err: false,
                                                            log: "Bootstrap Failed",
                                                            timestamp: timestampEnded
                                                        });
                                                        instanceModel.updateActionLog(instance.id, actionLog._id, false, timestampEnded);

                                                    }
                                                }

                                            }, function(stdOutData) {
                                                instanceLog.logs = {
                                                    err: false,
                                                    log: stdOutData.toString('ascii'),
                                                    timestamp: new Date().getTime()
                                                };
                                                instanceLogModel.createOrUpdate(actionLog._id, instance.id, instanceLog, function(err, logData) {
                                                    if (err) {
                                                        logger.error("Failed to create or update instanceLog: ", err);
                                                    }
                                                });

                                                logsDao.insertLog({
                                                    referenceId: logsReferenceIds,
                                                    err: false,
                                                    log: stdOutData.toString('ascii'),
                                                    timestamp: new Date().getTime()
                                                });

                                            }, function(stdErrData) {
                                                instanceLog.logs = {
                                                    err: true,
                                                    log: stdErrData.toString('ascii'),
                                                    timestamp: new Date().getTime()
                                                };
                                                instanceLogModel.createOrUpdate(actionLog._id, instance.id, instanceLog, function(err, logData) {
                                                    if (err) {
                                                        logger.error("Failed to create or update instanceLog: ", err);
                                                    }
                                                });

                                                //retrying 4 times before giving up.
                                                logsDao.insertLog({
                                                    referenceId: logsReferenceIds,
                                                    err: true,
                                                    log: stdErrData.toString('ascii'),
                                                    timestamp: new Date().getTime()
                                                });


                                            });
                                        });


                                    });
                                });
                            });


                        });
                    }
                    for (var ic = 0; ic < instanceDataAll.length; ic++) {
                        addInstanceWrapper(instanceDataAll[ic], instanceDataAll.length);
                    }
                });
            });
        });
    });
}



