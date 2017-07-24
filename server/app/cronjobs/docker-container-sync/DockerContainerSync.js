
var logger = require('_pr/logger')(module);
var CatalystCronJob = require('_pr/cronjobs/CatalystCronJob');
var MasterUtils = require('_pr/lib/utils/masterUtil.js');
var credentialCrpto = require('_pr/lib/credentialcryptography.js');
var resources = require('_pr/model/resources/resources.js');
var containerDao = require('_pr/model/container');
var auditTrailService = require('_pr/services/auditTrailService');
var SSH = require('_pr/lib/utils/sshexec');
var uuid = require('uuid');
var toPairs = require('lodash.topairs');
var async = require('async');
var logsDao = require('_pr/model/dao/logsdao.js');

var DockerContainerSync = Object.create(CatalystCronJob);
DockerContainerSync.interval = '*/2 * * * *';
DockerContainerSync.execute = dockerContainerSync;

module.exports = DockerContainerSync;

function dockerContainerSync() {
    MasterUtils.getAllActiveOrg(function (err, orgs) {
        if (err) {
            logger.error(err);
            return;
        } else if (orgs.length > 0) {
            for (var i = 0; i < orgs.length; i++) {
                (function (org) {
                    var query = {
                        'masterDetails.orgId': org.rowid,
                        'isDeleted':false,
                        'resourceDetails.dockerEngineState':'success'
                    }
                    resources.getResources(query, function (err, instances) {
                        if (err) {
                            logger.error(err);
                            return;
                        } else if (instances.length > 0) {
                            var count = 0;
                            for (var j = 0; j < instances.length; j++) {
                                (function (instance) {
                                    count++;
                                    aggregateDockerContainerForInstance(instance)
                                })(instances[j]);
                            }
                            if (count === instances.length) {
                                return;
                            }
                        } else {
                            logger.info("There is no Instance in " + org.orgname + " Organization who have docker installed");
                            return;
                        }
                    });
                })(orgs[i]);
            }
        } else {
            logger.info("There is no Active Organization for Docker Container Sync");
            return;
        }
    });
};


function aggregateDockerContainerForInstance(instance){
    logger.info("Docker Container Sync started for Instance IP "+instance.resourceDetails.publicIp);
    if(instance.resourceDetails.state === 'terminated' || instance.resourceDetails.state === 'stopped'){
        deleteContainerByInstanceId(instance,function(err,data){
            if(err){
                logger.error(err);
                return;
            }else{
                logger.debug("Deleted Docker Containers for Terminated or Stopped Instance");
                return;
            }
        })
    }else {
        var cmd = 'echo -e \"GET /containers/json?all=1 HTTP/1.0\r\n\" | sudo nc -U /var/run/docker.sock';
        async.waterfall([
            function (next) {
                credentialCrpto.decryptCredential(instance.resourceDetails.credentials, next);
            },
            function (decryptedCredentials, next) {
                var options = {
                    host: instance.resourceDetails.publicIp,
                    port: '22',
                    username: decryptedCredentials.username,
                    privateKey: decryptedCredentials.pemFileData,
                    password: decryptedCredentials.password
                };
                var sshParamObj = {
                    host: options.host,
                    port: options.port,
                    username: options.username
                };
                if (options.privateKey) {
                    sshParamObj.privateKey = options.privateKey;
                    if (options.passphrase) {
                        sshParamObj.passphrase = options.passphrase;
                    }
                } else {
                    sshParamObj.password = options.password;
                }
                var sshConnection = new SSH(sshParamObj);
                var stdOut = '';
                sshConnection.exec(cmd, function (err, code) {
                    if (err || code === -5000) {
                        var containerObj={
                            instanceId:instance._id,
                            operation:'delete'
                        }
                        next(null,containerObj);
                    }else {
                        var _stdout = stdOut.split('\r\n');
                        var start = false;
                        var so = '';
                        _stdout.forEach(function (k, v) {
                            if (start == true) {
                                so += _stdout[v];
                                logger.debug(v + ':' + _stdout[v].length);
                            }
                            if (_stdout[v].length == 1)
                                start = true;
                            if (v >= _stdout.length - 1) {
                                if (so.indexOf("Names") > 0) {
                                    var containers = JSON.parse(so);
                                    var containerList = [];
                                    var containerIds = [];
                                    for (var i = 0; i < containers.length; i++) {
                                        (function (container) {
                                            var containerName = container.Names[0].replace(/^\//, "");
                                            var status = dockerContainerStatus(container.Status.toString());
                                            var containerData = {
                                                orgId: instance.masterDetails.orgId,
                                                bgId: instance.masterDetails.bgId,
                                                projectId: instance.masterDetails.projectId,
                                                envId: instance.masterDetails.envId,
                                                Id: container.Id,
                                                instanceIP: instance.resourceDetails.publicIp,
                                                instanceId: instance._id,
                                                Names: containerName,
                                                Image: container.Image,
                                                ImageID: container.ImageID,
                                                Command: container.Command,
                                                Created: container.Created,
                                                Ports: container.Ports,
                                                Labels: toPairs(container.Labels),
                                                Status: container.Status,
                                                containerStatus: status,
                                                HostConfig: container.HostConfig
                                            };
                                            containerList.push(containerData);
                                            containerIds.push(container.Id);
                                        })(containers[i]);
                                    }
                                    if (containers.length === containerList.length) {
                                        var containerObj={
                                            containers:containerList,
                                            containerIds:containerIds,
                                            instanceId:instance._id,
                                            operation:'create'
                                        }
                                        next(null,containerObj);
                                    } else {
                                        logger.debug("There is no container present");
                                        next(null,null);
                                    }
                                } else {
                                    logger.debug("There is no container present");
                                    var containerObj={
                                        instanceId:instance._id,
                                        operation:'delete'
                                    }
                                    next(null,containerObj);
                                }
                            }
                        });
                    }
                }, function (stdOutData) {
                    stdOut += stdOutData.toString();
                }, function (stdOutErr) {
                    logger.error("Error hits to fetch docker details", stdOutErr);
                    next(stdOutErr,null);
                });
            },
            function(containers,next){
                if(containers.operation === 'delete'){
                    deleteContainerByInstanceId(containers.instanceId,next);
                }else if (containers.operation === 'create'){
                    saveAndUpdateContainers(containers.containers,containers.containerIds,containers.instanceId,instance,next)
                }else{
                    next(null,containers);
                }
            }
        ], function (err, results) {
            if (err) {
                logger.error("Error in Docker Container Sync");
                return;
            } else {
                logger.info("Docker Container Sync ended for Instance IP " + instance.instanceIP);
                return;
            }
        });
    }
};

function saveAndUpdateContainers(containers,containerIds,instanceId,instance,next){
    async.waterfall([
            function(next){
                containerDao.deleteContainersByContainerIds(instanceId,containerIds,next);
            },
            function(deleteContainers,next){
                var count = 0;
                for(var i = 0; i < containers.length; i++) {
                    (function(container) {
                        containerDao.getContainerByIdInstanceId(container.Id, instanceId, function(err,data){
                            if(err){
                                logger.error(err);
                                return;
                            }else if(data.length === 0){
                                containerDao.createContainer(container, function(err,containerData){
                                    if(err){
                                        logger.error(err);
                                        return;
                                    }else{
                                        count++;
                                        var containerStatus = container.Status;
                                        var actionObj = '',action ='',logs = '',actionId;
                                        if(containerStatus.indexOf('Paused') === -1){
                                            actionObj = 'Container-'+container.Names+'-Pause';
                                            action = 'Pause';
                                            actionId = 4;
                                            logs = "Docker-Container "+container.Names+" Paused";
                                        }else if(containerStatus.indexOf('Exited') === -1){
                                            actionObj = 'Container-'+container.Names+'-Stop';
                                            action = 'Stop';
                                            actionId = 2;
                                            logs = "Docker-Container "+container.Names+" Stopped";
                                        }else if(containerStatus.indexOf('Up') === -1){
                                            actionObj = 'Container-'+container.Names+'-Start';
                                            action = 'Start';
                                            logs = "Docker-Container "+container.Names+" Started";
                                        }
                                        var actionObj = 'Container-'+container.Names+'-Start';
                                        var timestampStarted = new Date().getTime();
                                        var actionLogId = uuid.v4();
                                        logsDao.insertLog({
                                            instanceId:instance._id,
                                            instanceRefId:actionLogId,
                                            err: false,
                                            log: logs,
                                            timestamp: timestampStarted
                                        });
                                        var containerLogs ={
                                            actionId: actionLogId,
                                            containerId: container.Id,
                                            orgName: instance.masterDetails.orgName,
                                            orgId: instance.masterDetails.orgId,
                                            bgName: instance.masterDetails.bgName,
                                            bgId: instance.masterDetails.bgId,
                                            projectName: instance.masterDetails.projectName,
                                            projectId: instance.masterDetails.projectId,
                                            envName: instance.masterDetails.envName,
                                            envId: instance.masterDetails.envId,
                                            status: action,
                                            actionStatus: "success",
                                            instanceIP:instance.resourceDetails.publicIp,
                                            platformId: instance.resourceDetails.platformId,
                                            containerName: container.Names,
                                            Image: container.Image,
                                            ImageID: container.ImageID,
                                            platform: instance.resourceDetails.hardware.platform,
                                            os: instance.resourceDetails.hardware.os,
                                            user: instance.catUser,
                                            createdOn: new Date().getTime(),
                                            startedOn: new Date().getTime(),
                                            providerType: instance.providerDetails.type ? instance.providerDetails.type:null,
                                            action: action
                                        };
                                        containerLogModel.createOrUpdate(containerLogs, function(err, logData){
                                            if (err) {
                                            logger.error("Failed to create or update containerLog: ", err);
                                            }
                                        });
                                        if(count === containers.length){
                                            next(null,containers);
                                        }
                                    }
                                });
                            }else{
                                containerDao.updateContainerStatus(container.Id, container.Status, container.containerStatus, function(err,deleteContainer){
                                    if(err){
                                        logger.error(err);
                                        return;
                                    }else{
                                        count++;
                                        if(count === containers.length){
                                            next(null,containers);
                                        }
                                    }
                                });
                            }
                        });
                    })(containers[i]);
                }

            }],
        function (err, results) {
            if(err){
                logger.error("Error in containerAction ");
                next(err);
            }else{
                next(null,results);
            }
        });
};

function dockerContainerStatus(status){
    if(status.indexOf('Exited') >= 0){
        return "STOP";
    }else if(status.indexOf('Paused')>= 0){
        return "PAUSE";
    }else{
        return "START";
    }
};

function deleteContainerByInstanceId(instanceDetails,next){
    var containerList = [];
    var count = 0;
    async.waterfall([
            function(next){
                containerDao.getContainerByInstanceId(instanceDetails._id,next);
            },
            function(containers,next){
                containerList = containers;
                containerDao.deleteContainerByInstanceId(instanceDetails._id,next);
            },
            function(containers,next){
                if(containerList.length > 0){
                    for(var i = 0; i < containerList.length;i++){
                        (function(container){
                            var timestampStarted = new Date().getTime();
                            var actionId = uuid.v4();
                            var actionObj = 'Container-'+container.Names+'-Terminated';
                            logsDao.insertLog({
                                instanceId:instanceDetails._id,
                                instanceRefId:actionId,
                                err: false,
                                log: actionObj,
                                timestamp: timestampStarted
                            });
                            var containerLog ={
                                actionId: actionId,
                                containerId: container.Id,
                                orgName: instanceDetails.masterDetails.orgName,
                                orgId: instanceDetails.masterDetails.orgId,
                                bgName: instanceDetails.masterDetails.bgName,
                                bgId: instanceDetails.masterDetails.bgId,
                                projectName: instanceDetails.masterDetails.projectName,
                                projectId: instanceDetails.masterDetails.projectId,
                                envName: instanceDetails.masterDetails.envName,
                                envId: instanceDetails.masterDetails.envId,
                                status: 'Terminated',
                                actionStatus: "success",
                                instanceIP:instanceDetails.resourceDetails.publicIp,
                                platformId: instanceDetails.resourceDetails.platformId,
                                containerName: container.Names,
                                Image: container.Image,
                                ImageID: container.ImageID,
                                platform: instanceDetails.resourceDetails.hardware.platform,
                                os: instanceDetails.resourceDetails.hardware.os,
                                user: instanceDetails.catUser,
                                createdOn: new Date().getTime(),
                                startedOn: new Date().getTime(),
                                providerType: instanceDetails.providerDetails.type ? instanceDetails.providerDetails.type:null,
                                action: 'Terminated'
                            };

                            containerLogModel.createOrUpdate(containerLog, function(err, logData){
                                if (err) {
                                    logger.error("Failed to create or update containerLog: ", err);
                                }
                                count++;
                            });
                            if(count === containers.length){
                                next(null,containers);
                            }
                        })(containerList[i]);
                    }
                }else{
                    next(null,containerList);
                }
        }
        ],
        function (err, results) {
            if(err){
                logger.error("Error in deleteContainerByInstanceId ");
                next(err);
            }else {
                next(null,results);
            }
        });
};

