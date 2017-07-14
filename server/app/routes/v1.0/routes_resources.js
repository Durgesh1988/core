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

var resourceService = require('_pr/services/resourceService');
var providerService = require('_pr/services/providerService');
var commonService = require('_pr/services/commonService');
var serviceMapService = require('_pr/services/serviceMapService');
var resources = require('_pr/model/resources/resources');
var async = require('async');
var apiUtil = require('_pr/lib/utils/apiUtil.js');
var settingService = require('_pr/services/settingsService');
var logsDao = require('_pr/model/dao/logsdao.js');
var userDao = require('_pr/model/users.js');
var logger = require('_pr/logger')(module);

module.exports.setRoutes = function(app, sessionVerificationFunc) {
    app.all("/resources*", sessionVerificationFunc);
    app.get('/resources',getAllResources);
    app.get('/resources/:resourceId',getResourceById);
    app.get('/resources/track/report',getResourceTrackReport);
    function getAllResources(req, res) {
            var reqObj = {};
            if(!req.query.paginationType) {
                async.waterfall(
                    [
                        function (next) {
                            apiUtil.changeRequestForJqueryPagination(req.query, next);
                        },
                        function (reqData, next) {
                            reqObj = reqData;
                            apiUtil.paginationRequest(reqData, 'resources', next);
                        },
                        function (paginationReq, next) {
                            if (paginationReq.filterBy && paginationReq.filterBy.resourceType && paginationReq.filterBy.resourceType === 'S3') {
                                paginationReq['searchColumns'] = ['resourceDetails.bucketName', 'resourceDetails.bucketOwnerName'];
                            }
                            if (paginationReq.filterBy && paginationReq.filterBy.resourceType && paginationReq.filterBy.resourceType === 'RDS') {
                                paginationReq['searchColumns'] = ['resourceDetails.dbName', 'resourceDetails.dbEngine', 'resourceDetails.dbInstanceClass', 'resourceDetails.region'];
                            }
                            if (paginationReq.filterBy && paginationReq.filterBy.resourceType && paginationReq.filterBy.resourceType === 'EC2') {
                                paginationReq['searchColumns'] = ['resourceDetails.platformId', 'resourceDetails.state', 'name', 'providerDetails.region.region'];
                            }
                            apiUtil.databaseUtil(paginationReq, next);
                        },
                        function (filterQuery, next) {
                            settingService.getOrgUserFilter(req.session.user.cn, function (err, orgIds) {
                                if (err) {
                                    next(err);
                                } else if (orgIds.length > 0) {
                                    filterQuery.queryObj['masterDetails.orgId'] = {$in: orgIds};
                                    next(null, filterQuery);
                                } else {
                                    next(null, filterQuery);
                                }
                            });
                        },
                        function (queryObj, next) {
                            if(req.query.monitor) {
                                if (req.query.monitor === 'true') {
                                    queryObj.queryObj.monitor = {$ne: null};
                                } else {
                                    queryObj.queryObj.monitor = null
                                }
                            }
                            resourceService.getResources(queryObj, true, next);
                        },
                        function (resources, next) {
                            apiUtil.changeResponseForJqueryPagination(resources, reqObj, next);
                        }
                    ], function (err, results) {
                        if (err) {
                            return res.status(500).send(err);
                        } else {
                            return res.status(200).send(results);
                        }
                    });
            }else{
                async.waterfall(
                    [
                        function(next){
                            apiUtil.paginationRequest(req.query, 'resources', next);
                        },
                        function(paginationReq, next) {
                            if(paginationReq.filterBy && paginationReq.filterBy.resourceType && paginationReq.filterBy.resourceType === 'S3'){
                                paginationReq['searchColumns'] = ['resourceDetails.bucketName','resourceDetails.bucketOwnerName'];
                            }
                            if(paginationReq.filterBy && paginationReq.filterBy.resourceType && paginationReq.filterBy.resourceType === 'RDS') {
                                paginationReq['searchColumns'] = ['resourceDetails.dbName','resourceDetails.dbEngine','resourceDetails.dbInstanceClass','resourceDetails.region'];
                            }
                            if(paginationReq.filterBy && paginationReq.filterBy.resourceType && paginationReq.filterBy.resourceType === 'EC2') {
                                paginationReq['searchColumns'] = ['resourceDetails.platformId','resourceDetails.state','name','providerDetails.region.region'];
                            }
                            reqObj = paginationReq;
                            apiUtil.databaseUtil(paginationReq, next);
                        },
                        function(filterQuery,next){
                            settingService.getOrgUserFilter(req.session.user.cn, function (err, orgIds) {
                                if (err) {
                                    next(err);
                                }else if(orgIds.length > 0){
                                    filterQuery.queryObj['masterDetails.orgId'] = { $in : orgIds };
                                    next(null,filterQuery);
                                }else{
                                    next(null,filterQuery);
                                }
                            });
                        },
                        function(queryObj, next) {
                            if(req.query.monitor) {
                                if (req.query.monitor === 'true') {
                                    queryObj.queryObj.monitor = {$ne: null};
                                } else {
                                    queryObj.queryObj.monitor = null
                                }
                            }
                            resourceService.getResources(queryObj,true, next);
                        },
                        function(resources,next){
                            apiUtil.paginationResponse(resources,reqObj,next);
                        }
                    ], function(err, results) {
                        if(err){
                            return res.status(500).send(err);
                        }else{
                            return res.status(200).send(results);
                        }
                    });
            }
    };

    function getResourceById(req,res){
        resources.getResourceById(req.params.resourceId,function(err,resource){
            if(err){
                return res.status(500).send(err);
            }else{
                return res.status(200).send(resource);
            }
        })
    };

    function getResourceTrackReport(req,res) {
        async.waterfall(
            [
                function (next) {
                    apiUtil.queryFilterBy(req.query, next);
                },
                function (queryObj, next) {
                    settingService.getOrgUserFilter(req.session.user.cn, function (err, orgIds) {
                        if (err) {
                            next(err);
                        }else if(orgIds.length > 0){
                            queryObj['masterDetails.orgId'] = { $in : orgIds };
                            next(null,queryObj);
                        }else{
                            next(null,queryObj);
                        }
                    });
                },
                function(filterQuery,next){
                    filterQuery.isDeleted = false;
                    resourceService.getResources(filterQuery,false, next);
                },
                function (resourceList, next) {
                    if(resourceList.length > 0){
                        var trackReport = {
                            totalResources:resourceList.length,
                            totalAssignedResources:0,
                            totalManagedResources:0,
                            totalUnAssignedResources:0,
                        }
                        resourceList.forEach(function(service){
                            if(service.category === 'managed'){
                                trackReport.totalManagedResources = trackReport.totalManagedResources + 1;
                            }else if(service.category === 'assigned'){
                                trackReport.totalAssignedResources = trackReport.totalAssignedResources + 1;
                            }else if(service.category === 'unassigned'){
                                trackReport.totalUnAssignedResources = trackReport.totalUnAssignedResources + 1;
                            }else{
                                logger.debug("Un-Supported Resource Type : ",service.category);
                            }
                        });
                        next(null,trackReport);
                    }else{
                        var trackReport = {
                            totalResources:resourceList.length,
                            totalAssignedResources:resourceList.length,
                            totalManagedResources:resourceList.length,
                            totalUnAssignedResources:resourceList.length,
                        }
                        next(null,trackReport);
                    }
                }
            ], function (err, results) {
                if(err){
                    return res.status(500).send(err);
                }else{
                    return res.status(200).send(results);
                }
            });
    }


    app.patch('/resources', updateUnassignedResourcesTags);
    
    function updateUnassignedResourcesTags(req,res,next){
        async.waterfall(
            [
                function (next) {
                    providerService.checkIfProviderExists(req.query.providerId, next);
                },
                function(provider, next) {
                    if('resources' in req.body) {
                        resourceService.bulkUpdateResourceProviderTags(provider, req.body.resources, next);
                    } else {
                        var err = new Error("Malformed request");
                        err.status = 400;
                        next(err);
                    }
                },
                function(resources, next) {
                    resourceService.bulkUpdateUnassignedResourceTags(req.body.resources, next);
                }
            ],
            function (err, results) {
                if (err) {
                    next(err);
                } else {
                    return res.status(200).send(results);
                }
            }
        );
    }

    app.patch('/resources/:resourceId/provider/:providerId/tags', updateUnassignedResourceTags);

    function updateUnassignedResourceTags(req,res,next){
        async.waterfall(
            [
                function (next) {
                    providerService.checkIfProviderExists(req.params.providerId, next);
                },
                function(provider, next) {
                    if('tags' in req.body) {
                        resourceService.updateAWSResourceTags(req.params.resourceId, provider, req.body.tags, next);
                    } else {
                        var err = new Error("Malformed request");
                        err.status = 400;
                        next(err);
                    }
                }
            ],
            function (err, results) {
                if (err) {
                    next(err);
                } else {
                    return res.status(200).send(results);
                }
            }
        );
    }


    app.post('/resources/:resourceId/authentication', function(req, res) {
        var credentials = null;
        if(req.body.credentials){
            credentials =req.body.credentials;
        }else{
            var error =  new Error();
            error.code = 500;
            error.message = "There is no Credentials Details for Resource"
            res.send(error);
        }
        serviceMapService.resourceAuthentication(req.params.resourceId,credentials,function(err,result){
            if(err){
                res.send(500,err);
                return;
            }else{
                res.send(result.code,result)
                return
            }
        });
    });

    app.post('/resources/importInstance', function(req, res) {
        async.waterfall(
            [
                function (next) {
                    userDao.haspermission(req.session.user.cn, 'instancelaunch', 'execute', null, req.session.user.permissionset, next)
                },
                function(importFlag, next) {
                    if(importFlag) {
                        req.body.user = req.session.user.cn;
                        resourceService.importInstance(req.body,next);
                    }else{
                        next({code:400,message:'User have no rights for Importing Instance'})
                    }
                }
            ],
            function (err, results) {
                if (err) {
                    return res.status(500).send(err);
                } else {
                    return res.status(200).send(results);
                }
            });
    });

    app.get('/resources/:resourceId/authenticate', function(req, res) {
        resources.getResourceById(req.params.resourceId,function(err,resource){
            if(err){
                res.send(500,err);
                return;
            }else if(resource !== null){
                res.send(200,resource.authentication?resource.authentication:null);
                return
            }else{
                var error = new Error("Resource is not exist in DB.");
                error.code = 403;
                error.message = "Resource is not exist in DB"
                res.send(403,err);
            }
        });
    });

    app.post('/resources/:resourceId/bootStrap', function(req, res) {
        commonService.bootStrappingResource(req.params.resourceId,function(err,result){
            if(err){
                res.send(500,err);
                return;
            }else{
                res.send(result.code,result)
                return
            }
        });
    });

    app.get('/resources/:resourceId/logs', function(req, res) {
        var queryObj = {
            instanceId:req.params.resourceId
        }
        if (req.query.timestamp && req.query.timestamp !== 'undefined') {
            queryObj.timestamp = {
                "$gt": parseInt(req.query.timestamp)
            }
        }
        if (req.query.timestampEnded && req.query.timestampEnded !== 'undefined') {
            queryObj.timestamp = {
                "$lte": parseInt(req.query.timestampEnded)
            }
        }
        logsDao.getLogsDetails(queryObj, function (err, data) {
            if (err) {
                logger.error("Found error to fetch Logs: ", err);
                res.send(500);
                return;
            }
            res.send(data);

        });
    });
};