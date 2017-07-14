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

// This file act as a Controller which contains organization related all end points.


var masterjsonDao = require('_pr/model/d4dmasters/masterjson.js');
var configmgmtDao = require('_pr/model/d4dmasters/configmgmt.js');
var Chef = require('_pr/lib/chef');
var SSHExec = require('_pr/lib/utils/sshexec');
var Puppet = require('_pr/lib/puppet');
var blueprintsDao = require('_pr/model/dao/blueprints');
var Blueprints = require('_pr/model/blueprint');
var usersDao = require('_pr/model/users.js');
var instancesDao = require('_pr/model/classes/instance/instance');
var containerDao = require('_pr/model/container');
var appConfig = require('_pr/config');
var logger = require('_pr/logger')(module);
var uuid = require('node-uuid');
var fileIo = require('_pr/lib/utils/fileio');
var logsDao = require('_pr/model/dao/logsdao.js');
var errorResponses = require('./error_responses');
var credentialCryptography = require('_pr/lib/credentialcryptography');
var d4dModelNew = require('_pr/model/d4dmasters/d4dmastersmodelnew.js');
var Curl = require('_pr/lib/utils/curl.js');
var waitForPort = require('wait-for-port');
var appCardsDao = require('_pr/model/dao/appcarddao');
var Application = require('_pr/model/classes/application/application');
var Task = require('_pr/model/classes/tasks/tasks.js');
var masterUtil = require('_pr/lib/utils/masterUtil.js');
var CloudFormation = require('_pr/model/cloud-formation');
var AzureArm = require('_pr/model/azure-arm');
var async = require('async');
var apiUtil = require('_pr/lib/utils/apiUtil.js');
var Docker = require('_pr/model/docker.js');
var orgValidator = require('_pr/validators/organizationValidator');
var validate = require('express-validation');
var taskService = require('_pr/services/taskService');
var instanceLogModel = require('_pr/model/log-trail/instanceLog.js');
var compositeBlueprintModel = require('_pr/model/composite-blueprints/composite-blueprints.js');
var Cryptography = require('_pr/lib/utils/cryptography');
var monitorsModel = require('_pr/model/monitors/monitors.js');
var catalystSync = require('_pr/cronjobs/catalyst-scheduler/catalystScheduler.js');
var botOldService = require('_pr/services/botOldService.js');
var organizationService = require('_pr/services/organizationService.js');


module.exports.setRoutes = function (app, sessionVerification) {
    /*
     * API without authentication provider to support telemetry.
     * @TODO To be moved to routes specific to containers.
     */
    app.get('/containers', function (req, res) {
        logger.debug("Enter get() for all docker Containers");
        containerDao.getAllContainers(function (err, containerList) {
            if (err) {
                logger.error(err);
                res.send(err);
                return;
            } else if (containerList.length === 0) {
                logger.debug("Presently,there is not container in catalyst");
                res.send(containerList);
                return;
            } else {
                res.send(containerList);
                return;
            }
        })
    });

    app.all('/organizations/*', sessionVerification);

    app.get('/organizations/getTreeNew', function (req, res) {
        logger.debug("Enter get() for /organizations/getTreeNew");
        var loggedInUser = req.session.user.cn;
        organizationService.getTreeNew(loggedInUser,"organization",function(err,results){
            if (err) {
                res.status(500).send(err);
                return;
            }else {
                res.status(200).send(results);
                return;
            }
        });
    });

    app.get('/organizations/getTreeForbtv', function (req, res) {
        logger.debug("Enter get() for /organizations/getTreeForbtv");
        var loggedInUser = req.session.user.cn;
        organizationService.getTreeForBtv(loggedInUser,"organization",function(err,results){
            if (err) {
                res.status(500).send(err);
                return;
            }else {
                res.status(200).send(results);
                return;
            }
        })
    });
    app.get('/organizations/:orgId/businessgroups/:bgId/projects/:projectId/environments/:envId/blueprints', function (req, res) {
        blueprintsDao.getBlueprintsByOrgBgProjectAndEnvId(req.params.orgId, req.params.bgId, req.params.projectId, req.params.envId, req.query.blueprintType, req.session.user.cn, function (err, data) {
            if (err) {
                res.send(500);
                return;
            }
            res.send(data);
        });
    });

    app.post('/organizations/:orgId/businessgroups/:bgId/projects/:projectId/blueprints', function (req, res) {
        logger.debug("Enter post() for /organizations/%s/businessgroups/%s/projects/%s/environments/%s/blueprints", req.params.orgId, req.params.bgId, req.params.projectId, req.params.envId, req.params.providerId, req.params.imageId);

        //validating if user has permission to save a blueprint
        logger.debug('Verifying User permission set');
        var user = req.session.user;
        var category = 'blueprints';
        var permissionto = 'create';
        var domainNameCheck = false;
        var manualExecutionTime = 10;
        var orgId = req.params.orgId;
        var bgId = req.params.bgId;
        var projectId = req.params.projectId;
        var name = req.body.blueprintData.name;
        var appUrls = req.body.blueprintData.appUrls;
        var iconpath = req.body.blueprintData.iconpath;
        var templateId = req.body.blueprintData.templateId;
        var templateType = req.body.blueprintData.templateType;
        var users = req.body.blueprintData.users || [];
        var blueprintType = req.body.blueprintData.blueprintType;
        var nexus = req.body.blueprintData.nexus;
        var docker = req.body.blueprintData.docker;
        var region = req.body.blueprintData.region;
        var blueprintId = req.body.blueprintData.blueprintId;
        var shortDesc = req.body.blueprintData.shortDesc;
        var botType = req.body.blueprintData.botType;
        var botCategory = req.body.blueprintData.botCategory;
        var serviceDeliveryCheck = req.body.blueprintData.serviceDeliveryCheck;
        if (req.body.blueprintData.manualExecutionTime && req.body.blueprintData.manualExecutionTime !== null) {
            manualExecutionTime = req.body.blueprintData.manualExecutionTime;
        }
        if (req.body.blueprintData.domainNameCheck === 'true') {
            domainNameCheck = true;
        }
        // a temp fix for invalid appurl data. will be removed in next iteration
        var tempAppUrls = [];
        if (!appUrls) {
            appUrls = []
        }
        for (var i = 0; i < appUrls.length; i++) {
            if (appUrls[i]) {
                tempAppUrls.push(appUrls[i]);
            }
        }
        appUrls = tempAppUrls;

        usersDao.haspermission(user.cn, category, permissionto, null, req.session.user.permissionset, function (err, data) {
            if (!err) {
                logger.debug('Returned from haspermission : ' + data + ' : ' + (data == false));
                if (data == false) {
                    logger.debug('No permission to ' + permissionto + ' on ' + category);
                    res.send(401);

                    return;
                }
            } else {
                logger.error("Hit and error in haspermission:", err);
                res.send(500);
                return;
            }
            logger.debug("Provider Id: ", req.body.blueprintData.providerId);
            if (!req.body.blueprintData.runlist) {
                req.body.blueprintData.runlist = [];
            }
            var blueprintData = {
                orgId: orgId,
                bgId: bgId,
                projectId: projectId,
                name: name,
                appUrls: appUrls,
                iconpath: iconpath,
                templateId: templateId,
                templateType: templateType,
                users: users,
                blueprintType: blueprintType,
                nexus: nexus,
                docker: docker,
                shortDesc: shortDesc,
                botType: botType,
                botCategory: botCategory,
                serviceDeliveryCheck: serviceDeliveryCheck,
                domainNameCheck: domainNameCheck,
                manualExecutionTime: manualExecutionTime
            };
            //adding bluerpintID if present (edit mode)
            if (blueprintId)
                blueprintData.id = blueprintId;

            logger.debug('req blueprintData:', blueprintData);
            var dockerData, instanceData;
            logger.debug('req.body.blueprintData.blueprintType:', blueprintType);
            if (blueprintType === 'docker') {
                dockerData = {
                    dockerContainerPathsTitle: req.body.blueprintData.dockercontainerpathstitle,
                    dockerContainerPaths: req.body.blueprintData.dockercontainerpaths,
                    dockerLaunchParameters: req.body.blueprintData.dockerlaunchparameters,
                    dockerRepoName: req.body.blueprintData.dockerreponame,
                    dockerCompose: req.body.blueprintData.dockercompose,
                    dockerRepoTags: req.body.blueprintData.dockerrepotags,
                    dockerImageName: req.body.blueprintData.dockerimagename,
                };
                blueprintData.dockerData = dockerData;

            } else if (blueprintType === 'instance_launch') {
                logger.debug('req.body.blueprintData.blueprintType ==>', blueprintType);
                logger.debug('req.body.blueprintData.region ==>', req.body.blueprintData.region);
                instanceData = {
                    keyPairId: req.body.blueprintData.keyPairId,
                    securityGroupIds: req.body.blueprintData.securityGroupIds,
                    instanceType: req.body.blueprintData.instanceType,
                    instanceAmiid: req.body.blueprintData.instanceAmiid,
                    instanceUsername: 'root',
                    vpcId: req.body.blueprintData.vpcId,
                    subnetId: req.body.blueprintData.subnetId,
                    region: req.body.blueprintData.region,
                    imageId: req.body.blueprintData.imageId,
                    cloudProviderType: 'aws',
                    cloudProviderId: req.body.blueprintData.providerId,
                    infraManagerType: 'chef',
                    infraManagerId: req.body.blueprintData.chefServerId,
                    runlist: req.body.blueprintData.runlist,
                    attributes: req.body.blueprintData.attributes,
                    instanceOS: req.body.blueprintData.instanceOS,
                    instanceCount: req.body.blueprintData.instanceCount
                }
                blueprintData.instanceData = instanceData;
            } else if (blueprintType === 'openstack_launch') {
                logger.debug('req.body.blueprintData.blueprintType ==>', blueprintType);
                instanceData = {
                    instanceImageID: req.body.blueprintData.imageIdentifier,
                    flavor: req.body.blueprintData.openstackflavor,
                    network: req.body.blueprintData.openstacknetwork,
                    securityGroupIds: [req.body.blueprintData.openstacksecurityGroupIds],
                    subnet: req.body.blueprintData.openstacksubnet,
                    instanceOS: req.body.blueprintData.instanceOS,
                    instanceCount: req.body.blueprintData.instanceCount,
                    cloudProviderType: 'openstack',
                    cloudProviderId: req.body.blueprintData.providerId,
                    infraManagerType: 'chef',
                    infraManagerId: req.body.blueprintData.chefServerId,
                    runlist: req.body.blueprintData.runlist,
                    attributes: req.body.blueprintData.attributes,
                    instanceImageName: req.body.blueprintData.instanceImageName

                }
                blueprintData.instanceData = instanceData;
            } else if (blueprintType === 'hppubliccloud_launch') {
                logger.debug('req.body.blueprintData.blueprintType ==>', blueprintType);
                instanceData = {
                    instanceImageID: req.body.blueprintData.imageIdentifier,
                    flavor: req.body.blueprintData.openstackflavor,
                    network: req.body.blueprintData.openstacknetwork,
                    securityGroupIds: req.body.blueprintData.openstacksecurityGroupIds,
                    subnet: req.body.blueprintData.openstacksubnet,
                    instanceOS: req.body.blueprintData.instanceOS,
                    instanceCount: req.body.blueprintData.instanceCount,
                    cloudProviderType: 'hppubliccloud',
                    cloudProviderId: req.body.blueprintData.providerId,
                    infraManagerType: 'chef',
                    infraManagerId: req.body.blueprintData.chefServerId,
                    runlist: req.body.blueprintData.runlist,
                    attributes: req.body.blueprintData.attributes,
                    instanceImageName: req.body.blueprintData.instanceImageName

                }
                blueprintData.instanceData = instanceData;
            } else if (blueprintType === 'azure_launch') {
                logger.debug('req.body.blueprintData.blueprintType ==>', blueprintType);
                instanceData = {
                    securityGroupIds: req.body.blueprintData.securityGroupPorts,
                    instanceType: req.body.blueprintData.instanceType,
                    instanceAmiid: req.body.blueprintData.instanceAmiid,
                    vpcId: req.body.blueprintData.vpcId,
                    subnetId: req.body.blueprintData.subnetId,
                    imageId: req.body.blueprintData.imageId,
                    region: req.body.blueprintData.region,
                    cloudProviderType: 'azure',
                    cloudProviderId: req.body.blueprintData.providerId,
                    infraManagerType: 'chef',
                    infraManagerId: req.body.blueprintData.chefServerId,
                    runlist: req.body.blueprintData.runlist,
                    attributes: req.body.blueprintData.attributes,
                    instanceOS: req.body.blueprintData.instanceOS,
                    instanceCount: req.body.blueprintData.instanceCount
                }
                blueprintData.instanceData = instanceData;
            } else if (blueprintType === 'vmware_launch') {
                logger.debug('req.body.blueprintData.blueprintType ==>', blueprintType);
                instanceData = {
                    dataStore: req.body.blueprintData.datastore,
                    imageId: req.body.blueprintData.imageId,
                    cloudProviderType: 'vmware',
                    cloudProviderId: req.body.blueprintData.providerId,
                    infraManagerType: 'chef',
                    infraManagerId: req.body.blueprintData.chefServerId,
                    runlist: req.body.blueprintData.runlist,
                    attributes: req.body.blueprintData.attributes,
                    instanceOS: req.body.blueprintData.instanceOS,
                    instanceCount: req.body.blueprintData.instanceCount
                }
                blueprintData.instanceData = instanceData;
            } else if (blueprintType === 'aws_cf') {
                logger.debug('templateFile ==> ', req.body.blueprintData.cftTemplateFile);
                var cloudFormationData = {
                    cloudProviderId: req.body.blueprintData.providerId,
                    infraManagerType: 'chef',
                    infraManagerId: req.body.blueprintData.chefServerId,
                    runlist: req.body.blueprintData.runlist,
                    stackParameters: req.body.blueprintData.cftStackParameters,
                    templateFile: req.body.blueprintData.cftTemplateFile,
                    region: req.body.blueprintData.region,
                    instances: req.body.blueprintData.cftInstances
                }
                blueprintData.cloudFormationData = cloudFormationData;
            } else if (req.body.blueprintData.blueprintType === 'azure_arm') {
                var armTemplateData = {
                    cloudProviderId: req.body.blueprintData.providerId,
                    infraManagerType: 'chef',
                    infraManagerId: req.body.blueprintData.chefServerId,
                    runlist: req.body.blueprintData.runlist,
                    stackParameters: req.body.blueprintData.cftStackParameters,
                    //stackName: req.body.blueprintData.stackName,
                    templateFile: req.body.blueprintData.cftTemplateFile,
                    resourceGroup: req.body.blueprintData.resourceGroup,
                    //instanceUsername: req.body.blueprintData.cftInstanceUserName
                    instances: req.body.blueprintData.cftInstances
                }
                blueprintData.armTemplateData = armTemplateData;
            } else {
                res.status(400).send({
                    message: "Invalid Blueprint Type"
                });
                return;
            }
            // if (!blueprintData.users || !blueprintData.users.length) {
            //  res.status(400).send({
            //      message: "User is empty"
            //  });
            //  return;
            // }
            Blueprints.createNew(blueprintData, function (err, bluePrintData) {
                if (err) {
                    logger.error('error occured while saving blueorint', err);
                    res.status(500).send({
                        message: "DB error"
                    });
                    return;
                }
                if (bluePrintData.serviceDeliveryCheck === true) {
                    masterUtil.getParticularProject(projectId, function (err, project) {
                        if (err) {
                            logger.error(err);
                        } else if (project.length > 0) {
                            bluePrintData.orgName = project[0].orgname;
                            bluePrintData.bgName = project[0].productgroupname;
                            bluePrintData.projectName = project[0].projectname;
                            botOldService.createOrUpdateBots(bluePrintData, 'Blueprint', blueprintType, function (err, botsData) {
                                if (err) {
                                    logger.error("Error in creating bots entry. " + err);
                                } else {
                                    logger.debug("Successfully added data for Bots.")
                                }
                            });
                        } else {
                            logger.debug("Unable to find Project Information from project id:");
                        }
                    });
                }
                res.send(data);
            });

            logger.debug("Exit post() for /organizations/%s/businessgroups/%s/projects/%s/environments/%s/providers/%s/images/%s/blueprints", req.params.orgId, req.params.bgId, req.params.projectId, req.params.envId, req.params.providerId, req.params.imageId);
        });
    });



    app.get('/organizations/:orgId/businessgroups/:bgId/projects/:projectId/environments/:envId/instances', function (req, res) {
        var jsonData = {};
        jsonData['orgId'] = req.params.orgId;
        jsonData['bgId'] = req.params.bgId;
        jsonData['projectId'] = req.params.projectId;
        jsonData['envId'] = req.params.envId;
        jsonData['instanceType'] = req.query.instanceType;
        jsonData['userName'] = req.session.user.cn;
        jsonData['id'] = 'instances';
        instancesDao.getInstancesByOrgBgProjectAndEnvId(jsonData, function (err, instancedata) {
            if (err) {
                res.send(500);
                return;
            }
            res.send(instancedata);
        });
    });

    app.get('/organizations/:orgId/businessgroups/:bgId/projects/:projectId/environments/:envId/tasks', function (req, res) {

        var jsonData = {};
        jsonData['orgId'] = req.params.orgId;
        jsonData['bgId'] = req.params.bgId;
        jsonData['projectId'] = req.params.projectId;
        jsonData['envId'] = req.params.envId;
        Task.getTasksByOrgBgProjectAndEnvId(jsonData, function (err, taskdata) {
            if (err) {
                res.send(500);
                return;
            }
            res.send(taskdata);
        });
    });

    app.get('/organizations/:orgId/businessgroups/:bgId/projects/:projectId/applications', function (req, res) {
        var jsonData = {};
        jsonData['orgId'] = req.params.orgId;
        jsonData['bgId'] = req.params.bgId;
        jsonData['projectId'] = req.params.projectId;
        Application.getAppCardsByOrgBgAndProjectId(jsonData, function (err, applications) {
            if (err) {
                res.send(500);
                return;
            }
            res.send(applications);
        });
    });

    app.get('/organizations/:orgId/businessgroups/:bgId/projects/:projectId/environments/:envId/taskList', validate(orgValidator.get), getTaskList);

    function getTaskList(req, res, next) {
        var reqData = {};
        async.waterfall([
            function (next) {
                apiUtil.paginationRequest(req.query, 'tasks', next);
            },
            function (paginationReq, next) {
                paginationReq['orgId'] = req.params.orgId;
                paginationReq['bgId'] = req.params.bgId;
                paginationReq['projectId'] = req.params.projectId;
                paginationReq['envId'] = req.params.envId;
                paginationReq['searchColumns'] = ['taskType', 'name'];
                reqData = paginationReq;
                apiUtil.databaseUtil(paginationReq, next);
            },
            function (queryObj, next) {
                queryObj['pagination'] = true;
                Task.getTasksByOrgBgProjectAndEnvId(queryObj, next);
            },
            function (tasks, next) {
                apiUtil.paginationResponse(tasks, reqData, next);
            }], function (err, results) {
            if (err) {
                res.send({
                    "errorCode": 500,
                    "message": "Error occured while fetching Task."
                });
            } else {
                return res.send(results);
            }
        });
    }

    app.get('/organizations/:orgId/businessgroups/:bgId/projects/:projectId/environments/:envId/chefTasks', validate(orgValidator.get), getChefTaskList);

    function getChefTaskList(req, res, next) {
        var jsonData = {};
        jsonData['orgId'] = req.params.orgId;
        jsonData['bgId'] = req.params.bgId;
        jsonData['projectId'] = req.params.projectId;
        jsonData['envId'] = req.params.envId;
        taskService.getChefTasksByOrgBgProjectAndEnvId(jsonData, function (err, chefTasks) {
            if (err) {
                logger.err(err);
                res.send(500);
                return;
            }
            res.send(chefTasks);
        });
    }

    app.get('/organizations/:orgId/businessgroups/:bgId/projects/:projectId/applicationList', validate(orgValidator.applications), getApplicationList);

    function getApplicationList(req, res, next) {
        var reqData = {};
        async.waterfall([
            function (next) {
                apiUtil.paginationRequest(req.query, 'applications', next);
            },
            function (paginationReq, next) {
                paginationReq['orgId'] = req.params.orgId;
                paginationReq['bgId'] = req.params.bgId;
                paginationReq['projectId'] = req.params.projectId;
                paginationReq['searchColumns'] = ['name', 'buildId'];
                reqData = paginationReq;
                apiUtil.databaseUtil(paginationReq, next);
            },
            function (queryObj, next) {
                queryObj['pagination'] = true;
                Application.getAppCardsByOrgBgAndProjectId(paginationReq, next);
            },
            function (applications, next) {
                apiUtil.paginationResponse(applications, reqData, next);
            }
        ], function (err, results) {
            if (err) {
                res.send({
                    "errorCode": 500,
                    "message": "Error occured while fetching Blueprints."
                });
            } else {
                return res.send(results);
            }
        });
    }





    app.get('/organizations/:orgId/businessgroups/:bgId/projects/:projectId/applications/:applicationId/build/:buildId', function (req, res) {
        Application.getApplicationById(req.params.applicationId, function (err, application) {
            if (err) {
                res.status(500).send(errorResponses.db.error);
                return;
            }
            if (application) {
                application.getBuild(function (err, build) {
                    if (err) {
                        res.status(500).send(errorResponses.db.error);
                        return;
                    }
                    res.send(build)
                });
            } else {
                res.send(404, {
                    message: "application not founds"
                });
            }
        });
    });

    app.post('/organizations/:orgId/businessgroups/:bgId/projects/:projectId/applications', function (req, res) {
        logger.debug(req.files);
        logger.debug(req.body.appData);
        logger.debug("Enter post() for /organizations/%s/businessgroups/%s/projects/%s/applications", req.params.orgId, req.params.bgId, req.params.projectId);
        var appData = req.body.appData;
        appData.orgId = req.params.orgId;
        appData.bgId = req.params.bgId;
        appData.projectId = req.params.projectId;
        Application.createNew(appData, function (err, data) {
            if (err) {
                res.send(500);
                return;
            }
            res.send(data);
        });
        logger.debug("Exit post() for /organizations/%s/businessgroups/%s/projects/%s/applications", req.params.orgId, req.params.bgId, req.params.projectId);
    });

    //Duplicated with provider filter for BP Edit

    app.get('/organizations/:orgId/businessgroups/:bgId/projects/:projectId/environments/:envId/', function (req, res) {
        var jsonData = {};
        jsonData['orgId'] = req.params.orgId;
        jsonData['bgId'] = req.params.bgId;
        jsonData['projectId'] = req.params.projectId;
        jsonData['envId'] = req.params.envId;
        jsonData['instanceType'] = req.params.instanceType;
        jsonData['userName'] = req.session.user.cn;
        jsonData['blueprintType'] = req.query.blueprintType


        configmgmtDao.getTeamsOrgBuProjForUser(req.session.user.cn, function (err, orgbuprojs) {
            if (orgbuprojs.length === 0) {
                res.send(401, "User not part of team to see project.");
                return;
            }
            if (!err) {
                if (typeof orgbuprojs[0].projects !== "undefined" && orgbuprojs[0].projects.indexOf(req.params.projectId) >= 0) {
                    async.parallel({
                        tasks: function (callback) {
                            Task.getTasksByOrgBgProjectAndEnvId(jsonData, callback);
                        },
                        instances: function (callback) {
                            instancesDao.getInstancesByOrgBgProjectAndEnvId(jsonData, callback);
                        },
                        blueprints: function (callback) {
                            Blueprints.getBlueprintsByOrgBgProject(jsonData, callback);
                        },
                        stacks: function (callback) {
                            CloudFormation.findByOrgBgProjectAndEnvId(jsonData, callback);
                        },
                        arms: function (callback) {
                            AzureArm.findByOrgBgProjectAndEnvId(jsonData, callback);
                        }
                    },
                        function (err, results) {
                            if (err) {
                                res.status(500).send("Internal Server Error");
                            } else if (!results) {
                                res.status(400).send("Data Not Found");
                            } else {
                                res.status(200).send(results);
                            }
                        }
                    );

                } else {
                    res.status(401).send("User not part of team to see project");
                    return;
                }
            } else {
                res.status(500).send("Internal Server Error");
                return;
            }
        });
    });

    app.post('/organizations/:orgId/businessgroups/:bgId/projects/:projectId/environments/:envId/tasks', function (req, res) {
        logger.debug("Enter post() for /organizations/%s/businessGroups/%s/projects/%s/environments/%s/tasks", req.params.orgId, req.params.bgId, req.params.projectId, req.params.environments);
        var taskData = req.body.taskData;
        taskData.orgId = req.params.orgId;
        taskData.bgId = req.params.bgId;
        taskData.projectId = req.params.projectId;
        taskData.envId = req.params.envId;
        taskData.autoSyncFlag = req.body.taskData.autoSyncFlag;
        masterUtil.getParticularProject(req.params.projectId, function (err, project) {
            if (err) {
                logger.error(err);
                res.status(500).send("Failed to get project via project id: ", err);
                return;
            }
            ;
            if (project.length === 0) {
                logger.error(err);
                res.status(500).send("Unable to find Project Information from project id: ", err);
                return;
            }
            taskData.orgName = project[0].orgname;
            taskData.bgName = project[0].productgroupname;
            taskData.projectName = project[0].projectname;
            if (taskData.taskScheduler && taskData.taskScheduler !== null && Object.keys(taskData.taskScheduler).length !== 0) {
                taskData.taskScheduler = apiUtil.createCronJobPattern(taskData.taskScheduler);
                taskData.isTaskScheduled = true;
            }
            if (taskData.taskType === 'jenkins') {
                taskData.executionOrder = 'PARALLEL';
            }
            if (taskData.manualExecutionTime && taskData.manualExecutionTime !== null) {
                taskData.manualExecutionTime = parseInt(taskData.manualExecutionTime);
            } else {
                taskData.manualExecutionTime = 10;
            }
            configmgmtDao.getEnvNameFromEnvId(req.params.envId, function (err, envName) {
                if (err) {
                    res.status(500).send("Failed to fetch ENV: ", err);
                    return;
                }
                taskData.envName = envName;
                if (taskData.taskType === 'script') {
                    encryptedParam(taskData.scriptDetails, function (err, encryptedParam) {
                        if (err) {
                            logger.error(err);
                            res.status(500).send("Failed to encrypted script parameters: ", err);
                            return;
                        } else {
                            taskData.scriptDetails = encryptedParam;
                            Task.createNew(taskData, function (err, task) {
                                if (err) {
                                    logger.error(err);
                                    res.status(500).send("Failed to create task: ", err);
                                    return;
                                }
                                if (task.isTaskScheduled === true) {
                                    if (task.executionOrder === 'PARALLEL') {
                                        catalystSync.executeParallelScheduledTasks();
                                    } else {
                                        catalystSync.executeSerialScheduledTasks();
                                    }
                                }
                                ;
                                if (task.serviceDeliveryCheck === true) {
                                    botOldService.createOrUpdateBots(task, 'Task', task.taskType, function (err, data) {
                                        if (err) {
                                            logger.error("Error in creating bots entry." + err);
                                        }
                                    });
                                }
                                res.send(task);
                                logger.debug("Exit post() for /organizations/%s/businessGroups/%s/projects/%s/environments/%s/tasks", req.params.orgId, req.params.bgId, req.params.projectId, req.params.environments);
                            });
                        }
                    })
                } else {
                    Task.createNew(taskData, function (err, task) {
                        if (err) {
                            logger.error(err);
                            res.status(500).send("Failed to create task: ", err);
                            return;
                        }
                        if (task.isTaskScheduled === true) {
                            if (task.executionOrder === 'PARALLEL') {
                                catalystSync.executeParallelScheduledTasks();
                            } else {
                                catalystSync.executeSerialScheduledTasks();
                            }

                        }
                        ;
                        if (task.serviceDeliveryCheck === true) {
                            botOldService.createOrUpdateBots(task, 'Task', task.taskType, function (err, data) {
                                if (err) {
                                    logger.error("Error in creating bots entry." + err);
                                }
                            });
                        }
                        res.send(task);
                        logger.debug("Exit post() for /organizations/%s/businessGroups/%s/projects/%s/environments/%s/tasks", req.params.orgId, req.params.bgId, req.params.projectId, req.params.environments);
                    });
                }
            });
        });
    });

    function encryptedParam(paramDetails, callback) {
        var cryptoConfig = appConfig.cryptoSettings;
        var cryptography = new Cryptography(cryptoConfig.algorithm, cryptoConfig.password);
        var count = 0;
        var encryptedList = [];
        for (var i = 0; i < paramDetails.length; i++) {
            (function (paramDetail) {
                if (paramDetail.scriptParameters.length > 0) {
                    count++;
                    for (var j = 0; j < paramDetail.scriptParameters.length; j++) {
                        (function (scriptParameter) {
                            var encryptedText = cryptography.encryptText(scriptParameter.paramVal, cryptoConfig.encryptionEncoding,
                                cryptoConfig.decryptionEncoding);
                            encryptedList.push({
                                paramVal: encryptedText,
                                paramDesc: scriptParameter.paramDesc,
                                paramType: scriptParameter.paramType
                            });
                            if (encryptedList.length === paramDetail.scriptParameters.length) {
                                paramDetail.scriptParameters = encryptedList;
                                encryptedList = [];
                            }
                        })(paramDetail.scriptParameters[j]);
                    }
                } else {
                    count++;
                }
                if (count === paramDetails.length) {
                    callback(null, paramDetails);
                    return;
                }
            })(paramDetails[i]);
        }
    }


    app.get('/organizations/:orgId/businessgroups/:bgId/projects/:projectId/environments/:envId/cftList', validate(orgValidator.get), getCftList);

    function getCftList(req, res, next) {
        var reqData = {};
        async.waterfall([
            function (next) {
                apiUtil.paginationRequest(req.query, 'cftList', next);
            },
            function (paginationReq, next) {
                paginationReq['orgId'] = req.params.orgId;
                paginationReq['bgId'] = req.params.bgId;
                paginationReq['projectId'] = req.params.projectId;
                paginationReq['envId'] = req.params.envId;
                paginationReq['searchColumns'] = ['stackName', 'status'];
                reqData = paginationReq;
                apiUtil.databaseUtil(paginationReq, next);
            },
            function (queryObj, next) {
                queryObj['pagination'] = true;
                CloudFormation.findByOrgBgProjectAndEnvId(queryObj, next);
            },
            function (cftData, next) {
                apiUtil.paginationResponse(cftData, reqData, next);
            }], function (err, results) {
            if (err) {
                res.send({
                    "errorCode": 500,
                    "message": "Error occured while fetching CFT."
                });
            } else {
                return res.send(results);
            }
        });
    }

    app.get('/organizations/:orgId/businessgroups/:bgId/projects/:projectId/environments/:envId/azureArmList', validate(orgValidator.get), getAzureArmList);

    function getAzureArmList(req, res, next) {
        var reqData = {};
        async.waterfall([
            function (next) {
                apiUtil.paginationRequest(req.query, 'azureArms', next);
            },
            function (paginationReq, next) {
                paginationReq['orgId'] = req.params.orgId;
                paginationReq['bgId'] = req.params.bgId;
                paginationReq['projectId'] = req.params.projectId;
                paginationReq['envId'] = req.params.envId;
                paginationReq['searchColumns'] = ['cloudProviderId', 'deploymentName'];
                reqData = paginationReq;
                apiUtil.databaseUtil(paginationReq, next);
            },
            function (queryObj, next) {
                queryObj['pagination'] = true;
                AzureArm.findByOrgBgProjectAndEnvId(queryObj, next);
            },
            function (armsData, next) {
                apiUtil.paginationResponse(armsData, reqData, next);
            }],
            function (err, results) {
                if (err) {
                    res.send({
                        "errorCode": 500,
                        "message": "Error occured while fetching Azure."
                    });
                } else {
                    return res.send(results);
                }
            });
    }

    app.get('/organizations/:orgId/businessgroups/:bgId/projects/:projectId/environments/:envId/containerList', validate(orgValidator.get), getContainerList);

    function getContainerList(req, res, next) {
        var reqData = {};
        async.waterfall([
            function (next) {
                apiUtil.paginationRequest(req.query, 'containerList', next);
            },
            function (paginationReq, next) {
                paginationReq['orgId'] = req.params.orgId;
                paginationReq['bgId'] = req.params.bgId;
                paginationReq['projectId'] = req.params.projectId;
                paginationReq['envId'] = req.params.envId;
                paginationReq['searchColumns'] = ['instanceIP', 'state'];
                reqData = paginationReq;
                apiUtil.databaseUtil(paginationReq, next);
            },
            function (queryObj, next) {
                queryObj['pagination'] = true;
                containerDao.getContainerListByOrgBgProjectAndEnvId(queryObj, next);
            },
            function (containerData, next) {
                apiUtil.paginationResponse(containerData, reqData, next);
            }], function (err, results) {
            if (err) {
                res.send({
                    "errorCode": 500,
                    "message": "Error occured while fetching Containers."
                });
            } else {
                return res.send(results);
            }
        });
    }
    ;

    app.get('/organizations/:orgId/chefserver', function (req, res) {
        logger.debug("Enter get() for /organizations/%s/chefserver", req.params.orgId);
        configmgmtDao.getChefServerDetailsByOrgname(req.params.orgId, function (err, chefDetails) {
            if (err) {
                res.send(500);
                return;
            }
            logger.debug("chefdata%s", chefDetails);
            if (!chefDetails) {
                res.send(404);
                return;
            } else {
                res.send(chefDetails);
                logger.debug("Exit get() for /organizations/%s/chefserver", req.params.orgId);
            }
        });
    });

    app.get('/organizations/:orgname/cookbooks', function (req, res) {
        logger.debug("Enter get() for /organizations/%s/cookbooks", req.params.orgname);
        configmgmtDao.getChefServerDetailsByOrgname(req.params.orgname, function (err, chefDetails) {
            if (err) {
                res.send(500);
                logger.error(err);
                return;
            }
            logger.debug("chefdata%s", chefDetails);


            if (!chefDetails) {
                res.send(404);
                return;
            }

            var chef = new Chef({
                userChefRepoLocation: chefDetails.chefRepoLocation,
                chefUserName: chefDetails.loginname,
                chefUserPemFile: chefDetails.userpemfile,
                chefValidationPemFile: chefDetails.validatorpemfile,
                hostedChefUrl: chefDetails.url,
            });

            chef.getCookbooksList(function (err, cookbooks) {

                if (err) {
                    logger.error('Unable to fetch cookbooks : ', err);
                    res.send(500);
                    return;
                } else {
                    res.send({
                        serverId: chefDetails.rowid,
                        cookbooks: cookbooks
                    });
                    logger.debug("Exit get() for /organizations/%s/cookbooks", req.params.orgname);
                }
            });

        });

    });

    app.get('/organizations/:orgname/roles', function (req, res) {
        logger.debug("Enter get() for /organizations/%s/roles", req.params.orgname);
        configmgmtDao.getChefServerDetailsByOrgname(req.params.orgname, function (err, chefDetails) {
            if (err) {
                res.send("There is some Internal Server Error. ", 500);
                return;
            }
            logger.debug("chefdata", chefDetails);

            if (!chefDetails) {
                res.send(404);
                return;
            }
            var chef = new Chef({
                userChefRepoLocation: chefDetails.chefRepoLocation,
                chefUserName: chefDetails.loginname,
                chefUserPemFile: chefDetails.userpemfile,
                chefValidationPemFile: chefDetails.validatorpemfile,
                hostedChefUrl: chefDetails.url,
            });

            chef.getRolesList(function (err, roles) {
                if (err) {
                    logger.error('Unable to fetch roles : ', err);
                    res.send(500);
                    return;
                } else {
                    res.send({
                        serverId: chefDetails.rowid,
                        roles: roles
                    });
                    logger.debug("Exit get() for /organizations/%s/roles", req.params.orgname);
                }
            });
        });
    });

    app.get('/organizations/:orgname/chefRunlist', function (req, res) {
        logger.debug("Enter get() for /organizations/%s/chefRunlist", req.params.orgname);
        configmgmtDao.getChefServerDetailsByOrgname(req.params.orgname, function (err, chefDetails) {
            if (err) {
                res.status(500).send(errorResponses.db.error);
                return;
            }
            logger.debug("chefdata", chefDetails);
            if (!chefDetails) {
                res.send(404, errorResponses.db.error);
                return;
            }
            var chef = new Chef({
                userChefRepoLocation: chefDetails.chefRepoLocation,
                chefUserName: chefDetails.loginname,
                chefUserPemFile: chefDetails.userpemfile,
                chefValidationPemFile: chefDetails.validatorpemfile,
                hostedChefUrl: chefDetails.url,
            });

            chef.getCookbooksList(function (err, cookbooks) {

                if (err) {
                    logger.error('Unable to fetch cookbooks : ', err);
                    res.status(500).send(errorResponses.chef.connectionError);
                    return;
                } else {
                    chef.getRolesList(function (err, roles) {

                        if (err) {
                            logger.error('Unable to fetch roles : ', err);
                            res.status(500).send(errorResponses.chef.connectionError);
                            return;
                        } else {
                            res.send({
                                serverId: chefDetails.rowid,
                                roles: roles,
                                cookbooks: cookbooks
                            });
                            logger.debug("Exit get() for /organizations/%s/chefRunlist", req.params.orgname);
                        }
                    });
                }
            });

        });

    });
    app.get('/organizations/usechefserver/:chefserverid/chefRunlist', function (req, res) {
        logger.debug("Enter get() for /organizations/usechefserver/%s/chefRunlist", req.params.orgname);
        configmgmtDao.getChefServerDetails(req.params.chefserverid, function (err, chefDetails) {
            if (err) {
                res.send(500);
                return;
            }
            logger.debug("chefdata", chefDetails);

            if (!chefDetails) {
                res.send(404);
                return;
            }
            var chef = new Chef({
                userChefRepoLocation: chefDetails.chefRepoLocation,
                chefUserName: chefDetails.loginname,
                chefUserPemFile: chefDetails.userpemfile,
                chefValidationPemFile: chefDetails.validatorpemfile,
                hostedChefUrl: chefDetails.url,
            });

            chef.getCookbooksList(function (err, cookbooks) {
                if (err) {
                    logger.error('Unable to fetch cookbooks : ', err);
                    res.send(500);
                    return;
                } else {
                    chef.getRolesList(function (err, roles) {

                        if (err) {
                            logger.error('Unable to fetch roles : ', err);
                            res.send(500);
                            return;
                        } else {
                            res.send({
                                serverId: chefDetails.rowid,
                                roles: roles,
                                cookbooks: cookbooks
                            });
                            logger.debug("Exit get() for /organizations/usechefserver/%s/chefRunlist", req.params.orgname);
                        }
                    });
                }
            });

        });

    });


    app.post('/organizations/:orgId/businessgroups/:bgId/projects/:projectId/blueprints/docker', function (req, res) {
        //validating if user has permission to save a blueprint
        logger.debug('Verifying User permission set');
        var user = req.session.user;
        var category = 'blueprints';
        var permissionto = 'create';

        usersDao.haspermission(user.cn, category, permissionto, null, req.session.user.permissionset, function (err, data) {
            if (!err) {
                logger.debug('Returned from haspermission : ' + data + ' : ' + (data == false));
                if (data == false) {
                    logger.debug('No permission to ' + permissionto + ' on ' + category);
                    res.send(401);

                    return;
                }
            } else {
                logger.error("Hit and error in haspermission:", err);
                res.send(500);
                return;
            }
            logger.debug("Provider Id: ", req.body.providerId);
            var blueprintData = req.body.blueprintData;
            blueprintData.orgId = req.params.orgId;
            blueprintData.bgId = req.params.bgId;
            blueprintData.projectId = req.params.projectId;
            blueprintData.envId = req.params.envId;

            // for Docker
            blueprintData.imageId = '000000';
            blueprintData.providerId = '000000';
            blueprintData.keyPairId = '000000';
            blueprintData.subnetId = '000000';
            blueprintData.vpcId = '000000';
            blueprintData.securityGroupIds = ['000000'];
            logger.debug("Enviornment ID:: ", req.params.envId);

            if (!blueprintData.runlist) {
                blueprintData.runlist = [];
            }
            if (!blueprintData.users || !blueprintData.users.length) {
                res.send(400);
                return;
            }

            blueprintsDao.createBlueprint(blueprintData, function (err, data) {
                if (err) {
                    res.send(500);
                    return;
                }
                res.send(data);
            });
            logger.debug("Exit post() for /organizations/%s/businessgroups/%s/projects/%s/environments/%s/providers/%s/images/%s/blueprints", req.params.orgId, req.params.bgId, req.params.projectId, req.params.envId, req.params.providerId, req.params.imageId);
        });
    });

    app.get('/organizations/:orgId/businessgroups/:bgId/projects/:projectId/environments/:envId/:provider', function (req, res) {
        var jsonData = {};
        jsonData['orgId'] = req.params.orgId;
        jsonData['bgId'] = req.params.bgId;
        jsonData['projectId'] = req.params.projectId;
        jsonData['envId'] = req.params.envId;
        jsonData['instanceType'] = req.params.instanceType;
        jsonData['userName'] = req.session.user.cn;
        jsonData['blueprintType'] = req.query.blueprintType;
        if (req.params.provider === null || req.params.provider === 'null') {
            jsonData['providerType'] = 'aws';
        } else {
            jsonData['providerType'] = req.params.provider;
        }
        configmgmtDao.getTeamsOrgBuProjForUser(req.session.user.cn, function (err, orgbuprojs) {
            if (orgbuprojs.length === 0) {
                res.send(401, "User not part of team to see project.");
                return;
            }
            if (!err) {
                if (typeof orgbuprojs[0].projects !== "undefined" && orgbuprojs[0].projects.indexOf(req.params.projectId) >= 0) {
                    async.parallel({
                        tasks: function (callback) {
                            Task.getTasksByOrgBgProjectAndEnvId(jsonData, callback);
                        },
                        instances: function (callback) {
                            instancesDao.getInstancesByOrgBgProjectAndEnvId(jsonData, callback);
                        },
                        blueprints: function (callback) {
                            Blueprints.getBlueprintsByOrgBgProjectProvider(jsonData, callback);
                        },
                        stacks: function (callback) {
                            CloudFormation.findByOrgBgProjectAndEnvId(jsonData, callback);
                        },
                        arms: function (callback) {
                            AzureArm.findByOrgBgProjectAndEnvId(jsonData, callback);
                        }
                    },
                        function (err, results) {
                            if (err) {
                                res.status(500).send("Internal Server Error");
                            } else if (!results) {
                                res.status(400).send("Data Not Found");
                            } else {
                                res.status(200).send(results);
                            }
                        }
                    );

                } else {
                    res.status(401).send("User not part of team to see project");
                    return;
                }
            } else {
                res.status(500).send("Internal Server Error");
                return;
            }
        });
    });

    // End point which will give list of all Docker instances for Org,BG,Proj and Env.
    app.get('/organizations/:orgId/businessgroups/:bgId/projects/:projectId/environments/:envId/docker/instances', function (req, res) {
        instancesDao.getInstancesByOrgBgProjectAndEnvForDocker(req.params.orgId, req.params.bgId, req.params.projectId, req.params.envId, function (err, instances) {
            if (err) {
                res.status(500).send({
                    "errorCode": 500,
                    "message": "Error occured while fetching docker instances."
                });
                return;
            }
            res.send(instances);
            return;
        });
    });


    app.get('/organizations/:orgId/businessgroups/:bgId/projects/:projectId/blueprintList', validate(orgValidator.applications), getBluePrintList);


    function getBluePrintList(req, res, next) {
        var reqData = {};
        async.waterfall([
            function (next) {
                apiUtil.paginationRequest(req.query, 'blueprints', next);
            },
            function (paginationReq, next) {
                if (req.query.templateType === 'composite') {
                    paginationReq['organizationId'] = req.params.orgId;
                    paginationReq['businessGroupId'] = req.params.bgId;
                    paginationReq['projectId'] = req.params.projectId;
                    paginationReq['cloudProviderType'] = req.query.providerType;
                    paginationReq['searchColumns'] = ['name'];
                } else {
                    paginationReq['orgId'] = req.params.orgId;
                    paginationReq['bgId'] = req.params.bgId;
                    paginationReq['projectId'] = req.params.projectId;
                    paginationReq['templateType'] = req.query.templateType;
                    paginationReq['blueprintConfig.cloudProviderType'] = req.query.providerType;
                    paginationReq['searchColumns'] = ['name'];
                }
                reqData = paginationReq;
                apiUtil.databaseUtil(paginationReq, next);

            },
            function (queryObj, next) {
                if (req.query.templateType === 'composite') {
                    compositeBlueprintModel.getCompositeBlueprintByOrgBgProject(queryObj, next)
                } else {
                    Blueprints.getBlueprintByOrgBgProjectProviderType(queryObj, next);
                }
            },
            function (blueprints, next) {
                if (req.query.pagination === 'true') {
                    apiUtil.paginationResponse(blueprints, reqData, next);
                } else {
                    next(null, blueprints.docs);
                }
            }], function (err, results) {
            if (err) {
                res.send({
                    "errorCode": 500,
                    "message": "Error occured while fetching Blueprints."
                });
            } else {
                return res.send(results);
            }
        });
    }

}

