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
var apiUtil = require('_pr/lib/utils/apiUtil.js');
var masterUtil = require('_pr/lib/utils/masterUtil.js');
var nexus = require('_pr/lib/nexus.js');
var AppData = require('_pr/model/app-deploy/app-data');
var utils = require('_pr/model/classes/utils/utils.js');
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



blueprintServices.launchABlueprint = function launchABlueprint(blueprintId,userDetails,queryParam, callback) {
    async.waterfall([
        

    ],function(err,results){
        if(err){
            callback(err,null);
        }
        callback(null,results);
    })

        var self = this;
        var domainName = launchParams.domainName;
        VMImage.getImageById(self.imageId, function(err, anImage) {
            if (err) {
                logger.error(err);
                callback({
                    message: "db-error"
                });
                return;
            }
            logger.debug("Loaded Image -- : >>>>>>>>>>> %s", anImage.providerId);
            // //determining osType and decrypting the password field if windows found
            // if(anImage.osType === 'windows'){
            //     anImage.instancePassword =
            // }

            AWSProvider.getAWSProviderById(anImage.providerId, function(err, aProvider) {
                if (err) {
                    logger.error(err);
                    callback({
                        message: "db-error"
                    });
                    return;
                }
                if (!aProvider) {
                    callback({
                        message: "Unable to fetch provider from DB"
                    });
                    return;
                }
                AWSKeyPair.getAWSKeyPairById(self.keyPairId, function(err, aKeyPair) {
                    if (err) {
                        logger.error(err);
                        callback({
                            message: "db-error"
                        });
                        return;
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

                    logger.debug("Enter launchInstance -- ");
                    // New add
                    //var encryptedPemFileLocation= currentDirectory + '/../catdata/catalyst/provider-pemfiles/';

                    var settings = appConfig;
                    //encrypting default pem file
                    var cryptoConfig = appConfig.cryptoSettings;
                    var cryptography = new Cryptography(cryptoConfig.algorithm, cryptoConfig.password);

                    //setting instance credentials when windows box is used.
                    var encrptedPassword;
                    var encryptedPemFileLocation;
                    if (anImage.instancePassword && anImage.instancePassword.length) {
                        encrptedPassword = anImage.instancePassword;
                    } else {
                        encryptedPemFileLocation = settings.instancePemFilesDir + aKeyPair._id;
                    }

                    var securityGroupIds = [];
                    for (var i = 0; i < self.securityGroupIds.length; i++) {
                        securityGroupIds.push(self.securityGroupIds[i]);
                    }

                    logger.debug("encryptFile of %s successful", encryptedPemFileLocation);

                    var ec2 = new EC2(awsSettings);
                    //Used to ensure that there is a default value of "1" in the count.
                    if (!self.instanceCount) {
                        self.instanceCount = "1";
                    }
                    var paramRunList = [];
                    var paramAttributes = [];
                    if (launchParams && launchParams.version) {
                        paramRunList = launchParams.version.runlist;
                        paramAttributes = launchParams.version.attributes;
                    }

                    ec2.launchInstance(anImage.imageIdentifier, self.instanceType, securityGroupIds, self.subnetId, 'D4D-' + launchParams.blueprintName, aKeyPair.keyPairName, self.instanceCount, function(err, instanceDataAll) {
                        if (err) {
                            logger.error("launchInstance Failed >> ", err);
                            callback({
                                // message: "Instance Launched Failed"
                                message: err.message
                            });
                            return;
                        }


                        var newinstanceIDs = [];

                        function addinstancewrapper(instanceData, instancesLength) {
                            logger.debug('Entered addinstancewrapper ++++++' + instancesLength);
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


                            logger.debug('Creating instance in catalyst');
                            instancesDao.createInstance(instance, function(err, data) {
                                if (err) {
                                    logger.error("Failed to create Instance", err);
                                    callback({
                                        message: "Failed to create instance in DB"
                                    });
                                    return;
                                }
                                instance = data;
                                instance.id = data._id;

                                //Returning handle when all instances are created
                                newinstanceIDs.push(instance.id);
                                logger.debug('Lengths ---- ' + newinstanceIDs.length + '  ' + instancesLength);
                                if (newinstanceIDs.length >= instancesLength) {
                                    callback(null, {
                                        "id": newinstanceIDs,
                                        "message": "instance launch success"
                                    });
                                }
                                var timestampStarted = new Date().getTime();
                                var actionLog = instancesDao.insertBootstrapActionLog(instance.id, instance.runlist, launchParams.sessionUser, timestampStarted);
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
                                //For windows instance handle another check..

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
                                    instancesDao.updateInstanceIp(instance.id, instance.instanceIP, function(err, updateCount) {
                                        if (err) {
                                            logger.error("instancesDao.updateInstanceIp Failed ==>", err);
                                            return;
                                        }
                                        logger.debug('Instance ip upadated');
                                    });
                                    instancesDao.updateInstanceState(instance.id, instanceData.State.Name, function(err, updateCount) {
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
                                            logger.error('intance wait failed ==> ', err);
                                            return;
                                        }

                                        logger.debug('intance wait success');


                                        //decrypting pem file
                                        var cryptoConfig = appConfig.cryptoSettings;
                                        var tempUncryptedPemFileLoc = appConfig.tempDir + uuid.v4();
                                        //cryptography.decryptFile(instance.credentials.pemFileLocation, cryptoConfig.decryptionEncoding, tempUncryptedPemFileLoc, cryptoConfig.encryptionEncoding, function(err) {
                                        credentialCryptography.decryptCredential(instance.credentials, function(err, decryptedCredentials) {

                                            if (err) {
                                                instancesDao.updateInstanceBootstrapStatus(instance.id, 'failed', function(err, updateData) {
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
                                                instancesDao.updateActionLog(instance.id, actionLog._id, false, timestampEnded);

                                                if (instance.hardware.os != 'windows')
                                                    return;
                                            }


                                            var repoData = {};
                                            repoData['projectId'] = launchParams.blueprintData.projectId;
                                            if (launchParams.blueprintData.nexus.repoName) {
                                                repoData['repoName'] = launchParams.blueprintData.nexus.repoName;
                                            } else if (launchParams.blueprintData.docker.image) {
                                                repoData['repoName'] = launchParams.blueprintData.docker.image;
                                            }


                                            launchParams.blueprintData.getCookBookAttributes(instance, repoData, function(err, jsonAttributes) {
                                                logger.debug("jsonAttributes::::: ", JSON.stringify(jsonAttributes));
                                                var runlist = instance.runlist;
                                                //logger.debug("launchParams.blueprintData.extraRunlist: ", JSON.stringify(launchParams.blueprintData.extraRunlist));
                                                if (launchParams.blueprintData.extraRunlist) {
                                                    runlist = launchParams.blueprintData.extraRunlist.concat(instance.runlist);
                                                }

                                                //logger.debug("runlist: ", JSON.stringify(runlist));
                                                var bootstrapInstanceParams = {
                                                    instanceIp: instance.instanceIP,
                                                    pemFilePath: decryptedCredentials.pemFileLocation,
                                                    runlist: runlist,
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


                                                    logger.error('process stopped ==> ', err, code);
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
                                                        instancesDao.updateInstanceBootstrapStatus(instance.id, 'failed', function(err, updateData) {

                                                        });
                                                        var timestampEnded = new Date().getTime();
                                                        logsDao.insertLog({
                                                            referenceId: logsReferenceIds,
                                                            err: true,
                                                            log: "Bootstrap failed",
                                                            timestamp: timestampEnded
                                                        });
                                                        instancesDao.updateActionLog(instance.id, actionLog._id, false, timestampEnded);


                                                    } else {
                                                        if (code == 0) {
                                                            instancesDao.updateInstanceBootstrapStatus(instance.id, 'success', function(err, updateData) {
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
                                                            instancesDao.updateActionLog(instance.id, actionLog._id, true, timestampEnded);
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
                                                                instancesDao.setHardwareDetails(instance.id, hardwareData, function(err, updateData) {
                                                                    if (err) {
                                                                        logger.error("Unable to set instance hardware details  code (setHardwareDetails)", err);
                                                                    } else {
                                                                        logger.debug("Instance hardware details set successessfully");
                                                                    }
                                                                });
                                                                //Checking docker status and updating
                                                                var _docker = new Docker();
                                                                _docker.checkDockerStatus(instance.id,
                                                                    function(err, retCode) {
                                                                        if (err) {
                                                                            logger.error("Failed _docker.checkDockerStatus", err);
                                                                            res.send(500);
                                                                            return;
                                                                            //res.end('200');

                                                                        }
                                                                        logger.debug('Docker Check Returned:' + retCode);
                                                                        if (retCode == '0') {
                                                                            instancesDao.updateInstanceDockerStatus(instance.id, "success", '', function(data) {
                                                                                logger.debug('Instance Docker Status set to Success');
                                                                            });

                                                                        }
                                                                    });

                                                            });

                                                        } else {
                                                            instancesDao.updateInstanceBootstrapStatus(instance.id, 'failed', function(err, updateData) {
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
                                                            instancesDao.updateActionLog(instance.id, actionLog._id, false, timestampEnded);

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


                            }); //end of create instance.
                        } //end of createinstancewrapper function


                        for (var ic = 0; ic < instanceDataAll.length; ic++) {
                            logger.debug('InstanceDataAll ' + JSON.stringify(instanceDataAll));
                            logger.debug('Length : ' + instanceDataAll.length);
                            addinstancewrapper(instanceDataAll[ic], instanceDataAll.length);
                        }
                    });
                });

            });

        });
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



