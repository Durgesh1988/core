
var logger = require('_pr/logger')(module);
var CatalystCronJob = require('_pr/cronjobs/CatalystCronJob');
var AWSProvider = require('_pr/model/classes/masters/cloudprovider/awsCloudProvider.js');
var MasterUtils = require('_pr/lib/utils/masterUtil.js');
var async = require('async');
var resourceService = require('_pr/services/resourceService');
var resourceModel = require('_pr/model/resources/resources');
var tagsModel = require('_pr/model/tags');
var instanceService = require('_pr/services/instanceService');
var commonService = require('_pr/services/commonService');
var noticeService = require('_pr/services/noticeService.js');
var saeService = require('_pr/services/saeService.js');
var credentialCryptography = require('_pr/lib/credentialcryptography');
var chefDao = require('_pr/model/dao/chefDao.js');
var apiUtil = require('_pr/lib/utils/apiUtil.js');



var AWSRDSS3ProviderSync = Object.create(CatalystCronJob);
AWSRDSS3ProviderSync.execute = awsRDSS3ProviderSync;

module.exports = AWSRDSS3ProviderSync;

function awsRDSS3ProviderSync() {
    MasterUtils.getAllActiveOrg(function(err, orgs) {
        if(err) {
            logger.error(err);
        }else if(orgs.length > 0){
            for(var i = 0; i < orgs.length; i++){
                (function(org){
                    AWSProvider.getAWSProvidersByOrgId(org.rowid, function(err, providers) {
                        if(err) {
                            logger.error(err);
                            return;
                        } else if(providers.length > 0){
                            var providerDetailList = [];
                            providers.forEach(function(provider){
                                providerDetailList.push(function(callback){awsRDSS3ProviderSyncForProvider(provider,org.orgname,callback);});
                            });
                            if(providerDetailList.length === providers.length) {
                                async.parallel(providerDetailList, function (err, results) {
                                    if (err) {
                                        logger.error(err);
                                        return;
                                    } else {
                                        logger.debug("Provider Sync is Completed");
                                        return;
                                    }
                                })
                            }
                        }else{
                            logger.info("Please configure Provider in Organization " +org.orgname+" for EC2/S3/RDS Provider Sync");
                            return;
                        }
                    });
                })(orgs[i]);
            }
        }else{
            logger.info("Please configure Organization for EC2/S3/RDS Provider Sync");
            return;
        }
    });
}

function awsRDSS3ProviderSyncForProvider(provider,orgName,callback) {
    logger.info("EC2/S3/RDS Data Fetching started for Provider "+provider.providerName);
    async.waterfall([
        function (next) {
            async.parallel({
                ec2: function (callback) {
                    resourceService.getEC2InstancesInfo(provider,orgName, callback);
                },
                s3: function (callback) {
                    resourceService.getBucketsInfo(provider,orgName, callback);
                },
                rds: function (callback) {
                    resourceService.getRDSInstancesInfo(provider,orgName, callback);
                }
            }, function (err, results) {
                if (err) {
                    next(err);
                } else {
                    next(null, results);
                }
            });
        },
        function (resources, next) {
            async.parallel({
                ec2: function (callback) {
                    saveEC2Data(resources.ec2,callback);
                },
                s3: function (callback) {
                    saveS3Data(resources.s3, callback);
                },
                rds: function (callback) {
                    saveRDSData(resources.rds, callback);
                },
                ec2Delete: function (callback) {
                    deleteEC2ResourceData(resources.ec2, provider._id, callback);
                },
                s3Delete: function (callback) {
                    deleteS3ResourceData(resources.s3, provider._id, callback);
                },
                rdsDelete: function (callback) {
                    deleteRDSResourceData(resources.rds, provider._id, callback);
                }
            }, function (err, results) {
                if (err) {
                    next(err);
                } else {
                    next(null, results);
                }
            });
        },
        function(resourcesDetails,next) {
            async.parallel({
                serviceSync: function (callback) {
                    saeService.serviceMapSync(callback);
                },
                saeSync: function (callback) {
                    saeSync(callback);
                },
                tagMapping: function (callback) {
                    resourceTagMapping(provider,callback);
                }
            }, function (err, results) {
                if (err) {
                    next(err,null);
                } else {
                    next(null, results);
                }
            })
        }],function (err, results) {
        if (err) {
            logger.error(err);
            callback(err,null);
            return;
        } else {
            logger.info("EC2/S3/RDS Data Successfully ended for Provider " +provider.providerName);
            callback(null,results);
            return;
        }
    });
};
function saveS3Data(s3Info, callback) {
    if(s3Info.length === 0) {
        return callback(null, s3Info);
    }else {
        var count = 0;
        for (var i = 0; i < s3Info.length; i++) {
            (function (s3) {
                var queryObj = {
                    'masterDetails.orgId':s3.masterDetails.orgId,
                    'providerDetails.id':s3.providerDetails.id,
                    'resourceDetails.bucketName':s3.resourceDetails.bucketName
                }
                resourceModel.getResources(queryObj, function (err, responseBucketData) {
                    if (err) {
                        logger.error("Error in getting Instance : ",s3.resourceDetails.bucketName);
                        count++;
                        if (count === s3Info.length) {
                            callback(null, s3Info);
                        }
                    }else if (responseBucketData.length > 0) {
                        var resourceObj = {
                            name:s3.name,
                            resourceDetails:s3.resourceDetails
                        }
                        resourceModel.updateResourceById(responseBucketData[0]._id,resourceObj, function (err, bucketUpdatedData) {
                            if (err) {
                                logger.error("Error in updating S3 Bucket : ",s3.resourceDetails.bucketName);
                            }
                            count++;
                            if (count === s3Info.length) {
                                callback(null, s3Info);
                            }
                        });
                    } else {
                        s3.createdOn = new Date().getTime();
                        resourceModel.createNew(s3, function (err, bucketSavedData) {
                            if (err) {
                                logger.error("Error in creating S3 Bucket : ",s3.resourceDetails.bucketName);
                            }
                            count++;
                            if (count === s3Info.length) {
                                callback(null, s3Info);
                            }
                        });
                    }
                })
            })(s3Info[i]);
        }
    }
}

function saveEC2Data(ec2Info,callback) {
    if(ec2Info.length === 0) {
        return callback(null, ec2Info);
    }else {
        var count = 0;
        for (var i = 0; i < ec2Info.length; i++) {
            (function (ec2) {
                var queryObj = {
                    'masterDetails.orgId': ec2.masterDetails.orgId,
                    'providerDetails.id': ec2.providerDetails.id,
                    'resourceDetails.platformId': ec2.resourceDetails.platformId
                }
                resourceModel.getResources(queryObj, function (err, responseInstanceData) {
                    if (err) {
                        logger.error("Error in getting Instance : ", ec2.resourceDetails.platformId);
                        count++;
                        if (count === ec2Info.length) {
                            callback(null, ec2Info);
                        }
                    } else if (responseInstanceData.length > 0) {
                        var resourceObj = {};
                        if (ec2.resourceDetails.state === 'shutting-down' || ec2.resourceDetails.state === 'terminated') {
                            resourceObj = {
                                'resourceDetails.state': ec2.resourceDetails.state,
                                'isDeleted': true
                            }
                        } else {
                            resourceObj = {
                                'tags': ec2.tags,
                                'resourceDetails.platformId': ec2.resourceDetails.platformId,
                                'resourceDetails.amiId': ec2.resourceDetails.amiId,
                                'resourceDetails.publicIp': ec2.resourceDetails.publicIp,
                                'resourceDetails.hostName': ec2.resourceDetails.hostName,
                                'resourceDetails.privateIp': ec2.resourceDetails.privateIp,
                                'resourceDetails.os': ec2.resourceDetails.os,
                                'resourceDetails.vpcId': ec2.resourceDetails.vpcId,
                                'resourceDetails.launchTime': ec2.resourceDetails.launchTime,
                                'resourceDetails.subnetId': ec2.resourceDetails.subnetId,
                                'resourceDetails.type': ec2.resourceDetails.type,
                                'resourceDetails.state': ec2.resourceDetails.state
                            }
                        }
                        resourceModel.updateResourceById(responseInstanceData[0]._id, resourceObj, function (err, instanceUpdatedData) {
                            if (err) {
                                logger.error("Error in updating Instance : ", ec2.resourceDetails.platformId);
                            }
                            count++;
                            if (count === ec2Info.length) {
                                callback(null, ec2Info);
                            }
                        });
                    } else {
                        ec2.createdOn = new Date().getTime();
                        resourceModel.createNew(ec2, function (err, instanceSavedData) {
                            if (err) {
                                logger.error("Error in creating Instance : ", ec2.resourceDetails.platformId);
                            }
                            count++;
                            if (count === ec2Info.length) {
                                callback(null, ec2Info);
                            }
                        });
                    }
                })
            })(ec2Info[i]);
        }
    }
}

function saveRDSData(rdsInfo, callback) {
    if(rdsInfo.length === 0) {
        return callback(null, rdsInfo);
    }else {
        var count = 0;
        for (var i = 0; i < rdsInfo.length; i++) {
            (function (rds) {
                var queryObj = {
                    'masterDetails.orgId':rds.masterDetails.orgId,
                    'providerDetails.id':rds.providerDetails.id,
                    'resourceDetails.dbiResourceId':rds.resourceDetails.dbiResourceId
                }
                resourceModel.getResources(queryObj, function (err, responseRDSData) {
                    if (err) {
                        logger.error("Error in getting RDS DBName : ",rds.resourceDetails.dbiResourceId);
                        count++;
                        if (count === rdsInfo.length) {
                            callback(null, rdsInfo);
                        }
                    }
                    if (responseRDSData.length > 0) {
                        var resourceObj = {
                            name:rds.name,
                            resourceDetails:rds.resourceDetails,
                        }
                        resourceModel.updateResourceById(responseRDSData[0]._id,resourceObj, function (err, rdsUpdatedData) {
                            if (err) {
                                logger.error("Error in updating RDS DBName : ",rds.resourceDetails.dbiResourceId);
                            }
                            count++;
                            if (count === rdsInfo.length) {
                                callback(null, rdsInfo);
                            }
                        });
                    } else {
                        rds.createdOn = new Date().getTime();
                        resourceModel.createNew(rds, function (err, rdsSavedData) {
                            if (err) {
                                logger.error("Error in creating RDS DBName : ",rds.resourceDetails.dbiResourceId);
                            }
                            count++;
                            if (count === rdsInfo.length) {
                                callback(null, rdsInfo);
                            }
                        });
                    }
                })
            })(rdsInfo[i]);
        }
    }
}

function deleteS3ResourceData(s3Info,providerId, callback) {
    if(s3Info.length === 0){
        resourceModel.deleteResourcesByResourceType('S3', function (err, data) {
            if (err) {
                callback(err,null);
                return;
            } else {
                callback(null,s3Info);
                return;
            }
        });
    }else {
        async.waterfall([
            function (next) {
                bucketNameList(s3Info, next);
            },
            function (bucketNames, next) {
                var queryObj = {
                    'providerDetails.id':providerId,
                    'resourceType': 'S3'
                };
                resourceModel.getResources(queryObj, function (err, s3data) {
                    if (err) {
                        next(err);
                    } else {
                        next(null, s3data, bucketNames);
                    }
                });
            },
            function (s3Data, bucketNames, next) {
                if (s3Data.length > 0) {
                    var count = 0;
                    for (var i = 0; i < s3Data.length; i++) {
                        (function (s3) {
                            if (bucketNames.indexOf(s3.resourceDetails.bucketName) === -1) {
                                resourceModel.deleteResourcesById(s3._id, function (err, data) {
                                    if (err) {
                                        logger.error("Error in deleting S3 Bucket :",s3.resourceDetails.bucketName)
                                    }
                                    count++;
                                    if (count === s3Data.length) {
                                        next(null, s3Data);
                                    }
                                })
                            } else {
                                count++;
                                if (count === s3Data.length) {
                                    next(null, []);
                                }
                            }
                        })(s3Data[i]);
                    }
                } else {
                    next(null, bucketNames);
                }
            }], function (err, results) {
            if (err) {
                callback(err, null);
                return;
            }
            callback(null, results);
            return;
        })
    }
}

function deleteEC2ResourceData(ec2Info,providerId, callback) {
    if (ec2Info.length === 0) {
        resourceModel.deleteResourcesByResourceType('EC2', function (err, data) {
            if (err) {
                callback(err, null);
                return;
            } else {
                callback(null, ec2Info);
                return;
            }
        });
    } else {
        async.waterfall([
            function (next) {
                ec2PlatformIdList(ec2Info, next);
            },
            function (platformIds, next) {
                var queryObj = {
                    'providerDetails.id': providerId,
                    'resourceType': 'EC2'
                };
                resourceModel.getResources(queryObj, function (err, ec2data) {
                    if (err) {
                        return next(err, null);
                    } else if (ec2data.length > 0) {
                        var count = 0;
                        for (var i = 0; i < ec2data.length; i++) {
                            (function (ec2) {
                                if (platformIds.indexOf(ec2.resourceDetails.platformId) === -1) {
                                    resourceModel.deleteResourcesById(ec2._id, function (err, data) {
                                        if (err) {
                                            logger.error("Error in deleting EC2 Instance :", ec2.resourceDetails.platformId)
                                        }
                                        count++;
                                        if (count === ec2data.length) {
                                            return next(null, ec2data);
                                        }
                                    })
                                } else {
                                    count++;
                                    if (count === ec2data.length) {
                                        return next(null, []);
                                    }
                                }
                            })(ec2data[i]);
                        }
                    } else {
                        return next(null, platformIds);
                    }
                });
        }], function (err, results) {
            if (err) {
                return callback(err, null);
            } else {
                return callback(null, results);
            }
        })
    }
}

function deleteRDSResourceData(rdsInfo,providerId, callback) {
    if(rdsInfo.length === 0){
        resourceModel.deleteResourcesByResourceType('RDS', function (err, data) {
            if (err) {
                callback(err,null);
                return;
            } else {
                callback(null,rdsInfo);
                return;
            }
        });
    }else {
        async.waterfall([
            function (next) {
                rdsDBResourceIdList(rdsInfo, next);
            },
            function (rdsDBResourceIds, next) {
                var queryObj = {
                    'providerDetails.id':providerId,
                    'resourceType': 'RDS'
                };
                resourceModel.getResources(queryObj, function (err, rdsData) {
                    if (err) {
                        next(err);
                    } else {
                        next(null, rdsData, rdsDBResourceIds);
                    }
                });
            },
            function (rdsData, rdsDBResourceIds, next) {
                if (rdsData.length > 0) {
                    var count = 0;
                    for (var i = 0; i < rdsData.length; i++) {
                        (function (rds) {
                            if (rdsDBResourceIds.indexOf(rds.resourceDetails.dbiResourceId) === -1) {
                                resourceModel.deleteResourcesById(rds._id, function (err, data) {
                                    if (err) {
                                        logger.error("Error in deleting RDS DBName :",rds.resourceDetails.dbiResourceId)
                                    }
                                    count++;
                                    if (count === ec2data.length) {
                                        next(null, ec2data);
                                    }
                                })
                            } else {
                                count++;
                                if (count === rdsData.length) {
                                    next(null, []);
                                }
                            }
                        })(rdsData[i]);
                    }
                } else {
                    next(null, rdsData);
                }
            }], function (err, results) {
            if (err) {
                callback(err, null);
                return;
            }
            callback(null, results);
            return;
        })
    }
}

function resourceTagMapping(provider,callback){
    logger.debug("Tag Mapping is started");
    async.waterfall([
        function (next) {
            var queryObj = {
                'providerDetails.id':provider._id,
                'category':'unassigned'
            };
            resourceModel.getResources(queryObj, next);
        },
        function (resources, next) {
            tagMappingSyncForResources(resources, provider, 'unassigned', next);
        },
        function (resources, next) {
            var queryObj = {
                'providerDetails.id':provider._id,
                'category':'assigned'
            };
            resourceModel.getResources(queryObj, next);
        },
        function (assignedResources, next) {
            tagMappingSyncForResources(assignedResources, provider, 'assigned', next);
        }],function (err, data) {
        if (err) {
            logger.error("Error in Tag-Mapping: ",err);
            return callback(err, null);
        } else {
            logger.debug("Tag-Mapping is Done");
            return callback(null, data);
        }
    })
}

function tagMappingSyncForResources(resources,provider,category,next){
    tagsModel.getTagsByProviderId(provider._id, function (err, tagDetails) {
        if (err) {
            logger.error("Unable to get tags", err);
            next(err);
        }
        var projectTag = null;
        var environmentTag = null;
        var bgTag = null;
        if (tagDetails.length > 0) {
            for (var i = 0; i < tagDetails.length; i++) {
                if (('catalystEntityType' in tagDetails[i]) && tagDetails[i].catalystEntityType == 'project') {
                    projectTag = tagDetails[i];
                } else if (('catalystEntityType' in tagDetails[i]) && tagDetails[i].catalystEntityType == 'environment') {
                    environmentTag = tagDetails[i];
                } else if (('catalystEntityType' in tagDetails[i]) && tagDetails[i].catalystEntityType == 'businessGroup') {
                    bgTag = tagDetails[i];
                }
            }
            if(projectTag === null && environmentTag === null && bgTag === null){
                logger.info("There is no Tag Mapping");
                next(null,tagDetails);
            }else if (resources.length > 0) {
                var count = 0;
                for (var j = 0; j < resources.length; j++) {
                    (function (resource) {
                        if (resource.tags) {
                            var catalystProjectId = null;
                            var catalystProjectName = null;
                            var catalystEnvironmentId = null;
                            var catalystEnvironmentName = null;
                            var catalystBgId = null;
                            var catalystBgName = null;

                            if (bgTag !== null && bgTag.name in resource.tags) {
                                var bgEntityMappings = Object.keys(bgTag.catalystEntityMapping).map(
                                    function (k) {
                                        return bgTag.catalystEntityMapping[k]
                                    });

                                for (var y = 0; y < bgEntityMappings.length; y++) {
                                    if ((resource.tags[bgTag.name] !== '') && ('tagValues' in bgEntityMappings[y])
                                        && (bgEntityMappings[y].tagValues.indexOf(resource.tags[bgTag.name])
                                        >= 0)) {
                                        catalystBgId = bgEntityMappings[y].catalystEntityId;
                                        catalystBgName = bgEntityMappings[y].catalystEntityName;
                                        break;
                                    }
                                }
                            }
                            if (projectTag !== null && projectTag.name in resource.tags) {
                                var projectEntityMappings = Object.keys(projectTag.catalystEntityMapping).map(
                                    function (k) {
                                        return projectTag.catalystEntityMapping[k]
                                    });

                                for (var y = 0; y < projectEntityMappings.length; y++) {
                                    if ((resource.tags[projectTag.name] !== '') && ('tagValues' in projectEntityMappings[y])
                                        && (projectEntityMappings[y].tagValues.indexOf(resource.tags[projectTag.name])
                                        >= 0)) {
                                        catalystProjectId = projectEntityMappings[y].catalystEntityId;
                                        catalystProjectName = projectEntityMappings[y].catalystEntityName;
                                        break;
                                    }
                                }
                            }
                            
                            if (environmentTag !== null && environmentTag.name in resource.tags) {
                                
                                var environmentEntityMappings = Object.keys(environmentTag.catalystEntityMapping).map(
                                    function (k) {
                                        return environmentTag.catalystEntityMapping[k]
                                    });
                                 for (var y = 0; y < environmentEntityMappings.length; y++) {
                                    if ((resource.tags[environmentTag.name] !== '')
                                        && ('tagValues' in environmentEntityMappings[y])
                                        && (environmentEntityMappings[y].tagValues.indexOf(
                                            resource.tags[environmentTag.name]) >= 0)) {
                                        catalystEnvironmentId = environmentEntityMappings[y].catalystEntityId;
                                        catalystEnvironmentName = environmentEntityMappings[y].catalystEntityName;
                                        break;
                                    }
                                }
                            }
                            if ((catalystBgId !== null || catalystProjectId !== null || catalystEnvironmentId !== null) && category ==='unassigned') {
                                var fields = {
                                    masterDetails: {
                                        orgId: resource.masterDetails.orgId,
                                        orgName: resource.masterDetails.orgName,
                                        bgId: catalystBgId,
                                        bgName: catalystBgName,
                                        projectId: catalystProjectId,
                                        projectName: catalystProjectName,
                                        envId: catalystEnvironmentId,
                                        envName: catalystEnvironmentName
                                    },
                                    category:'assigned'
                                }
                                resourceModel.updateResourceById(resource._id, fields, function (err, data) {
                                    if (err) {
                                        logger.error(err);
                                    }
                                    count++;
                                    if (count === resources.length) {
                                        next(null, resources);
                                        return;
                                    }
                                })
                            } else if ((catalystBgId !== null || catalystProjectId !== null || catalystEnvironmentId !== null) && category ==='assigned') {
                                var masterDetails= {
                                    "masterDetails.bgId": catalystBgId,
                                    "masterDetails.bgName": catalystBgName,
                                    "masterDetails.projectId": catalystProjectId,
                                    "masterDetails.projectName": catalystProjectName,
                                    "masterDetails.envId": catalystEnvironmentId,
                                    "masterDetails.envName": catalystEnvironmentName
                                };
                                resourceModel.updateResourceById(resource._id,masterDetails,function(err,data){
                                    if(err){
                                        logger.error("Unable to update master details of assigned Resource", err);
                                    }
                                    count++;
                                    if(count === resources.length) {
                                        next(null, resources);
                                        return;
                                    }
                                });
                            } else if(category === 'assigned') {
                                resourceModel.removeResourceById(resource._id,function(err,data){
                                    if(err){
                                        logger.error("Unable to remove assigned Resource", err);
                                    }
                                    count++;
                                    if(count === resources.length) {
                                        next(null, resources);
                                        return;
                                    }
                                });
                            } else {
                                count++;
                                if (count === resources.length) {
                                    next(null, resources);
                                    return;
                                }
                            }
                        }else{
                            count++;
                            if (count === resources.length) {
                                next(null, resources);
                                return;
                            }
                        }
                          
                    })(resources[j]);
                }
            }
        } else if (category === 'assigned') {
            logger.info("There is no Tag Mapping");
            var queryObj = {
                category : 'assigned',
                'providerDetails.id':provider._id
            }
            resourceModel.removeResources(queryObj, function (err, data) {
                if (err) {
                    logger.error("Unable to remove assigned Resource", err);
                    next(err);
                    return;
                } else {
                    logger.info("Please configure Resources for Tag Mapping");
                    next(null, data);
                    return;
                }
            });
        } else {
            logger.info("Please configure Resources for Tag Mapping");
            next(null, resources);
        }
    });
}

function bucketNameList(s3Info,callback){
    var bucketNames=[];
    for(var i = 0; i < s3Info.length; i++){
        bucketNames.push(s3Info[i].resourceDetails.bucketName);
    }
    callback(null,bucketNames);
}

function rdsDBResourceIdList(rdsInfo,callback){
    var rdsDBResourceIds=[];
    for(var i = 0; i < rdsInfo.length; i++){
        rdsDBResourceIds.push(rdsInfo[i].resourceDetails.dbiResourceId);
    }
    callback(null,rdsDBResourceIds);
}

function ec2PlatformIdList(ec2Info,callback){
    var ec2PlatformIds=[];
    for(var i = 0; i < ec2Info.length; i++){
        ec2PlatformIds.push(ec2Info[i].resourceDetails.platformId);
    }
    callback(null,ec2PlatformIds);
}

function saeSync(callback){
    logger.debug("SAE Sync is stared");
    async.waterfall([
        function(next){
            resourceModel.getResources({isDeleted:false,category:'managed'},next);
        },
        function(instances,next){
            if(instances.length > 0){
                instanceSync(instances,next);
            }else{
                logger.debug("There is no instance present in DB without terminated state");
                next(null,instances);
            }
        }
    ],function(err,results){
        if(err){
            logger.error("There are some error in SAE Sync.",err);
            return callback(err,null);
        }else{
            logger.debug("SAE Sync is Done");
            return callback(null,results);
        }

    })
}

function instanceSync(instances,callback){
    var count = 0,credentials = {};
    instances.forEach(function(instance){
        if(instance.providerDetails && instance.providerDetails.id !== null){
            count++;
            if(count === instances.length){
                return callback(null,instances);
            }
        }else{
            var nodeDetails = {
                nodeIp: instance.resourceDetails.publicIp,
                nodeOs: instance.resourceDetails.hardware.os,
                nodeName: instance.resourceDetails.platformId
            }
            instance.credentials['source'] = 'executor';
            credentialCryptography.decryptCredential(instance.credentials, function (err, decryptedCredentials) {
                if (decryptedCredentials.fileData) {
                    credentials = {
                        "username": decryptedCredentials.username,
                        "pemFileData": decryptedCredentials.decryptedData,
                        "pemFileLocation": instance.credentials.pemFileLocation
                    }
                } else {
                    credentials = {
                        "username": decryptedCredentials.username,
                        "password": decryptedCredentials.password
                    }
                }
                commonService.checkNodeCredentials(nodeDetails,credentials,function(err,credentialFlag){
                    if(err){
                        logger.error("Error in checking credentials of a instance : ",instance.platformId,err);
                    }
                    if(credentialFlag === true) {
                        count++;
                        if(count === instances.length){
                            callback(null,instances);
                        }
                    }else{
                        resourceModel.deleteResourcesById(instance._id, function (err, data) {
                            if (err) {
                                logger.error(err);
                            }
                            count++;
                            if (count === instances.length) {
                                callback(null, instances);
                                return;
                            }
                        })
                    }
                })
            });
        }
    })
}
