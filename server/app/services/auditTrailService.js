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
var instanceAuditTrail = require('_pr/model/audit-trail/instance-audit-trail.js');
var botAuditTrail = require('_pr/model/audit-trail/bot-audit-trail.js');
var containerAuditTrail = require('_pr/model/audit-trail/container-audit-trail.js');
var auditTrail = require('_pr/model/audit-trail/audit-trail.js');
var botOld = require('_pr/model/bots/1.0/botOld.js');
var botDao = require('_pr/model/bots/1.1/bot.js');
var ObjectId = require('mongoose').Types.ObjectId;

const errorType = 'auditTrailService';

var auditTrailService = module.exports = {};
var async = require('async');
var apiUtil = require('_pr/lib/utils/apiUtil.js');
var logsDao = require('_pr/model/dao/logsdao.js');
var serviceNow = require('_pr/model/servicenow/servicenow.js');
var settingService = require('_pr/services/settingsService');
var orgResourcePermission = require('_pr/model/org-resource-permission/orgResourcePermission.js');
var d4dModelNew = require('_pr/model/d4dmasters/d4dmastersmodelnew.js');


auditTrailService.insertAuditTrail = function insertAuditTrail(auditDetails,auditTrailConfig,actionObj,callback) {
    var auditTrailObj = {
        auditId: auditDetails._id,
        auditType: actionObj.auditType,
        actionLogId:auditTrailConfig.actionLogId?auditTrailConfig.actionLogId:null,
        masterDetails:{
            orgId: auditDetails.orgId?auditDetails.orgId:auditDetails.masterDetails.orgId,
            orgName: auditDetails.orgName?auditDetails.orgName:auditDetails.masterDetails.orgName,
            bgId: auditDetails.bgId?auditDetails.bgId:auditDetails.masterDetails.bgId,
            bgName: auditDetails.bgName?auditDetails.bgName:auditDetails.masterDetails.bgName,
            projectId: auditDetails.projectId?auditDetails.projectId:auditDetails.masterDetails.projectId,
            projectName: auditDetails.projectName?auditDetails.projectName:auditDetails.masterDetails.projectName,
            envId: auditDetails.envId?auditDetails.envId:auditDetails.masterDetails.envId,
            envName: auditDetails.envName?auditDetails.envName:auditDetails.environmentName?auditDetails.environmentName:auditDetails.masterDetails.envName
        },
        status: actionObj.status,
        auditCategory:actionObj.auditCategory,
        actionStatus: actionObj.actionStatus,
        user: actionObj.catUser,
        startedOn: new Date().getTime(),
        action: actionObj.action
    };
    if(actionObj.auditType === 'BOTOLD' || actionObj.auditType === 'BOT'){
        auditTrailObj.auditTrailConfig = auditTrailConfig;
        botAuditTrail.createNew(auditTrailObj,function(err,data){
            if(err){
                logger.error(err);
                callback(err,null);
                return;
            }
            callback(null,data);
            return;
        })
    }else if(actionObj.auditType === 'Instances'){
        auditTrailObj.auditTrailConfig = auditTrailConfig;
        instanceAuditTrail.createNew(auditTrailObj,function(err,data){
            if(err){
                logger.error(err);
                callback(err,null);
                return;
            }
            callback(null,data);
            return;
        })
    }else if(actionObj.auditType === 'Containers'){
        auditTrailObj.auditTrailConfig = auditTrailConfig;
        containerAuditTrail.createNew(auditTrailObj,function(err,data){
            if(err){
                logger.error(err);
                callback(err,null);
                return;
            }
            callback(null,data);
            return;
        })
    }else{
        callback({
            message: "Invalid Audit Trail Type. "
        }, null);
    }
}

auditTrailService.updateAuditTrail = function updateAuditTrail(auditType,auditId,auditObj,callback) {
    if(auditType === 'BOTOLD' || auditType === 'BOT'){
        botAuditTrail.updateBotAuditTrail(auditId,auditObj,function(err,data){
            if(err){
                logger.error(err);
                callback(err,null);
                return;
            }
            callback(null,data);
            async.parallel({
                botServiceNowSync:function(callback){
                    var botAuditTrailService = require('_pr/services/auditTrailService.js');
                    botAuditTrailService.syncCatalystWithServiceNow(auditId,function(err,data){
                        if(err){
                            logger.error("Error in updating Service Now Ticket Details:");
                            callback(err,null);
                        }else{
                            logger.debug("ServiceNow sync is Done.")
                            callback(err,null);
                        }
                    });
                },
                botExecutionLastStatus:function(callback){
                    async.waterfall([
                        function(next){
                            auditTrail.getAuditTrails({_id:new ObjectId(auditId)},next)
                        },
                        function(botAuditTrail,next){
                            if(botAuditTrail.length > 0 && auditObj.status
                                && (auditObj.status !== null || auditObj.status !== '')){
                                var botService = require('_pr/services/botService.js');
                                botService.updateLastBotExecutionStatus(botAuditTrail[0].auditId,auditObj.status,function(err,data){
                                    if(err){
                                        logger.error("Error in updating Last Execution Time Details:");
                                        callback(err,null);
                                    }else{
                                        logger.debug("ServiceNow sync is Done.")
                                        callback(err,null);
                                    }
                                });
                            }else{
                                next({code:400,message:"There is no records are available for BOTS Last Execution Status"},null);
                            }
                        },

                    ],function(err,results){
                        if(err){
                            callback(err,null);
                            return;
                        }else{
                            callback(null,results);
                            return;
                        }
                    })
                }
            },function(err,results){
                if(err){
                    logger.error(JSON.stringify(err));
                    return;
                }else{
                    logger.debug(results);
                    return;
                }
            })
        })
    }else if(auditType === 'Instances'){
        instanceAuditTrail.updateInstanceAuditTrail(auditId,auditObj,function(err,data){
            if(err){
                logger.error(err);
                callback(err,null);
                return;
            }
            callback(null,data);
            return;
        })
    }else if(auditType === 'Containers'){
        containerAuditTrail.updateContainerAuditTrail(auditId,auditObj,function(err,data){
            if(err){
                logger.error(err);
                callback(err,null);
                return;
            }
            callback(null,data);
            return;
        })
    }else{
        callback({
            message: "Invalid Audit Trail Type. "
        }, null);
    }
}

auditTrailService.getAuditTrailList = function getAuditTrailList(auditTrailQuery,callback) {
    var reqData = {};
    async.waterfall([
        function(next) {
            apiUtil.paginationRequest(auditTrailQuery, 'auditTrails', next);
        },
        function(paginationReq, next) {
            paginationReq['searchColumns'] = ['status', 'action', 'user', 'actionStatus', 'auditTrailConfig.name','masterDetails.orgName', 'masterDetails.bgName', 'masterDetails.projectName', 'masterDetails.envName'];
            reqData = paginationReq;
            apiUtil.databaseUtil(paginationReq, next);
        },
        function(queryObj, next) {
            auditTrail.getAuditTrailList(queryObj, next);
        },
        function(auditTrailList, next) {
            apiUtil.paginationResponse(auditTrailList, reqData, next);
        }
    ],function(err, results) {
        if (err){
            logger.error(err);
            callback(err,null);
            return;
        }
        callback(null,results)
        return;
    });
}

auditTrailService.syncCatalystWithServiceNow = function syncCatalystWithServiceNow(auditTrailId,callback){
    var srnTicketNo = null;
    async.waterfall([
        function(next){
            auditTrail.getAuditTrailsById(auditTrailId,next)
        },
        function(botAuditTrail,next){
            if(botAuditTrail.length > 0 && botAuditTrail[0].auditTrailConfig.serviceNowTicketRefObj
            && (botAuditTrail[0].auditTrailConfig.serviceNowTicketRefObj !== null || botAuditTrail[0].auditTrailConfig.serviceNowTicketRefObj !== '')){
                srnTicketNo = botAuditTrail[0].auditTrailConfig.serviceNowTicketRefObj.ticketNo;
                serviceNow.getCMDBList(function(err,srnServerDetails) {
                    if (err) {
                        next(err, null);
                    } else if (srnServerDetails.length > 0) {
                        var tableName = 'incident';
                        var config = {
                            username: srnServerDetails[0].servicenowusername,
                            password: srnServerDetails[0].servicenowpassword,
                            host: srnServerDetails[0].url,
                            ticketNo: srnTicketNo
                        };
                        serviceNow.getConfigItems(tableName, config, function (err, ticketData) {
                            if (err) {
                                logger.error("Error in Getting Servicenow Config Items:", err);
                                next(err, null);
                                return;
                            } else if (!ticketData.result) {
                                logger.error("ServiceNow CI data fetch error");
                                next({
                                    code: 303,
                                    message: "No Data is available in ServiceNow against ticketNo:" + srnTicketNo
                                }, null);
                                return;
                            } else {
                                var serviceNowObj = {
                                    ticketNo: srnTicketNo,
                                    ticketLink: srnServerDetails[0].url + '/api/now/table/' + tableName + "?number=" + srnTicketNo,
                                    shortDesc: ticketData.result[0].short_description,
                                    desc: ticketData.result[0].description,
                                    openedAt: toTimestamp(ticketData.result[0].opened_at),
                                    createdOn: toTimestamp(ticketData.result[0].sys_created_on),
                                    closedAt: toTimestamp(ticketData.result[0].closed_at),
                                    updatedOn: toTimestamp(ticketData.result[0].sys_updated_on),
                                    resolvedAt: toTimestamp(ticketData.result[0].resolved_at),
                                    state: checkServiceNowTicketState(ticketData.result[0].state),
                                    priority: checkServiceNowTicketPriority(ticketData.result[0].priority),
                                    category: ticketData.result[0].category
                                };
                                var request = require('request');
                                var host = ticketData.result[0].resolved_by.link.replace(/.*?:\/\//g, "");
                                var serviceNowURL = 'https://' + config.username + ':' + config.password + '@' + host;
                                var options = {
                                    url: serviceNowURL,
                                    headers: {
                                        'User-Agent': 'request',
                                        'Accept': 'application/json'
                                    }
                                };
                                request(options, function (error, response, body) {
                                    if (!error && response.statusCode == 200) {
                                        var info = JSON.parse(body);
                                        serviceNowObj.resolvedBy = info.result.user_name;
                                    } else {
                                        serviceNowObj.resolvedBy = "admin";
                                    }
                                    botAuditTrail.updateBotAuditTrail(auditTrailId, {
                                        'auditTrailConfig.serviceNowTicketRefObj': serviceNowObj
                                    }, function (err, data) {
                                        if (err) {
                                            logger.error(err);
                                            next(err, null);
                                            return;
                                        } else {
                                            next(null, data);
                                            return;
                                        }
                                    })
                                });
                            }
                        });
                    } else {
                        logger.info("There is no Service Now Server details available. Please configure first for serviceNow Syncing");
                        next(null,null);
                    }
                });
            }else{
                logger.info("There is no records are available for Service Now Ticket Sync");
                next(null,null);
            }
        }

    ],function(err,results){
        if(err){
            callback(err,null);
            return;
        }else{
            callback(null,results);
            return;
        }
    })
}

auditTrailService.getAuditTrailActionLogs = function getAuditTrailActionLogs(actionId,timeStamp,callback){
    var queryObj = {
        instanceRefId:actionId
    }
    if (timeStamp) {
        queryObj.timestamp = {
            "$gt": parseInt(timeStamp)
        };
    }
    logsDao.getLogsDetails(queryObj, function(err,actionLogs){
        if (err){
            logger.error(err);
            callback(err,null);
            return;
        }
        callback(null,actionLogs)
        return;
    });
}

auditTrailService.getBOTsSummary = function getBOTsSummary(queryParam,BOTSchema,userName,callback){
	var teamId;
	var filterByOrg = false;
    async.waterfall([
        function(next){
            apiUtil.queryFilterBy(queryParam,next);
        },
        function(filterQuery,next) {
        	var orgId = filterQuery.orgId;
        	teamId = filterQuery.teamId;
        	delete filterQuery.teamId;
            filterQuery.isDeleted=false;
            if(BOTSchema === 'BOTOLD') {
                settingService.getOrgUserFilter(userName,function(err,orgIds){
                    if(err){
                        next(err,null);
                    }else if(orgIds.length > 0){
                        filterQuery.orgId = {$in:orgIds};
    	                botOld.getAllBots(filterQuery, next);
                    }else{
                        botOld.getAllBots(filterQuery, next);
                    }
                });
            }else{
                settingService.getOrgUserFilter(userName,function(err,orgIds){
                    if(err){
                        next(err,null);
                    }else if(orgIds.length > 0){
                        filterQuery.orgId = {$in:orgIds};
                    }
                    d4dModelNew.d4dModelMastersUsers.find({
	                    loginname: userName,
	                    id:'7'
	                }, function(err, userDetails) {
	                	
	                	if ( err ) {
	                		return next(err, null);
	                	}
	                	var userDetail = {};
	                	if (userDetails.length > 0) {
	                		userDetail = userDetails[0];
	                		userDetail.orgname_rowid = (typeof userDetail.orgname_rowid[0]) !== undefined ? userDetail.orgname_rowid[0] : userDetail.orgname_rowId;
	                		userDetail.orgname = (typeof userDetail.orgname[0]) !== undefined ? userDetail.orgname[0] : userDetail.orgname;
	                	}
	                	var teamIds;
	                	if (teamId) {
         				   filterByOrg = true;
         				   teamIds = [teamId];
         			   	}
	                	var ids = [];
	                	if ( userDetail.userrolename === 'Admin') {
            			   getOrgResourceList((orgId || userDetail.orgname_rowid), (teamIds || [] ), function(err, orgBotsList){
            				   if ( err ){
            					   next(err,null);
            				   }
            				   if (filterByOrg) {
            					   orgBotsList.forEach(function(orgBot){
            						   ids = ids.concat(orgBot.resourceIds);
            					   });
            				   }
            				   if (ids.length > 0) {
            					   filterQuery.id = {$in:ids};
            				   }
            				   if (orgId) {
            					   filterQuery.orgId = orgId;
            				   }
            				   if (orgId && teamId && orgBotsList.length === 0) {
            					   return next(null, []);
            				   }
            				   botDao.getAllBots(filterQuery, next);
            			   });
	            		}else {
 	            		   getOrgResourceList(userDetail.orgname_rowid, userDetail.teamname_rowid.split(','), function(err, orgBotsList){
 	            			  if ( err ){
 	            				  next(err,null);
 	            			  } 
 	            			  orgBotsList.forEach(function(orgBot){
     						   ids = ids.concat(orgBot.resourceIds);
 	            			  });
 	            			  
 	            			  if (ids.length > 0) {
 	            				 filterQuery.id = {$in:ids};
 	            			  } else {
 	            				  return next(null, []);
 	            			  }
 	            			  botDao.getAllBots(filterQuery, next);
 	            		   });
	 	            	}
	                });
                });
            }
        },
        function(botsList,next){
            async.parallel({
                totalNoOfBots: function(callback){
                            callback(null, botsList.length);
                },
                totalNoOfSuccessBots: function(callback){
                    var successCount = 0;
                    for(var i = 0; i < botsList.length; i++){
                        if(botsList[i].successExecutionCount){
                            successCount = successCount + botsList[i].successExecutionCount;
                        }
                    }
                    callback(null,successCount);
                },
                totalNoOfServiceNowTickets: function(callback){
                    var srnCount = 0;
                    for(var i = 0; i < botsList.length; i++){
                        if(botsList[i].srnSuccessExecutionCount){
                            srnCount = botsList[i].srnSuccessExecutionCount;
                        }
                    }
                    callback(null,srnCount);
                },
                totalNoOfRunningBots: function(callback){
                    var runningCount = 0;
                    for(var i = 0; i < botsList.length; i++){
                        if(botsList[i].runningExecutionCount){
                            runningCount = runningCount + botsList[i].runningExecutionCount;
                        }
                    }
                    callback(null,runningCount);
                },
                totalSavedTimeForBots: function(callback){
                    var days =0,hours = 0, minutes = 0, seconds = 0;
                    if(botsList.length > 0) {
                        for (var k = 0; k < botsList.length; k++) {
                            if(botsList[k].savedTime && botsList[k].savedTime.days && botsList[k].savedTime.days > 0) {
                                days = days + botsList[k].savedTime.days;
                            }
                            if(botsList[k].savedTime && botsList[k].savedTime.hours && botsList[k].savedTime.hours > 0) {
                                hours = hours + botsList[k].savedTime.hours;
                            }
                            if(botsList[k].savedTime && botsList[k].savedTime.minutes && botsList[k].savedTime.minutes > 0){
                                minutes = minutes + botsList[k].savedTime.minutes;
                            }
                            if(botsList[k].savedTime && botsList[k].savedTime.seconds && botsList[k].savedTime.seconds > 0){
                                seconds = seconds + botsList[k].savedTime.seconds;
                            }
                        }
                    }
                    if(seconds >= 60){
                        minutes = minutes + Math.floor(seconds / 60);
                        seconds = seconds % 60;
                    }
                    if(minutes >= 60){
                        hours = hours + Math.floor(minutes / 60);
                        minutes = minutes % 60;
                    }
                    if(hours >= 24){
                        days = days + Math.floor(hours / 24);
                        hours = minutes % 24
                    }
                    var result = {
                        days:days,
                        hours:hours,
                        minutes:minutes,
                        seconds:seconds
                    }
                    callback(null,result);
                },
                totalNoOfFailedBots: function(callback){
                    var failedCount = 0;
                    for(var i = 0; i < botsList.length; i++){
                        if(botsList[i].failedExecutionCount){
                            failedCount = failedCount + botsList[i].failedExecutionCount;
                        }
                    }
                    callback(null,failedCount);
                }

            },function(err,data){
                if(err){
                    logger.error(err);
                    next(err,null);
                }
                next(null,data);
            })
        }
    ],function(err,results){
        if(err){
            logger.error(err);
            callback(err,null);
            return;
        }
        callback(null,results);
        return;
    })
}

function getOrgResourceList(orgId, teamIds, callback){
	if (orgId){
	   var query = {
		   orgId : orgId,
		   resourceType : 'bots'
	   };
	   
	   if(teamIds.length > 0) {
		  query.teamId = {$in : teamIds};
	   }
	   
	   orgResourcePermission.find(query, function(err, orgResourceList){
		   if ( err ) {
			   return callback(err, null);
		   }
		   
		   return callback(null, orgResourceList);
	   });
	} else {
		return callback(null, []);
	}
}

auditTrailService.getBotsAuditTrailHistory = function getBotsAuditTrailHistory(botId,callback){
    var query={
        auditType:'BOTOLD',
        auditId:botId,
        isDeleted:false
    };
    auditTrail.getAuditTrails(query,function(err,data){
        if(err){
            callback(err,null);
        }else {
            callback(null, data);
        }
    });
}

auditTrailService.softRemoveAuditTrailById = function softRemoveAuditTrailById(auditId,callback){
    auditTrail.softRemoveAuditTrails(auditId,function(err,data){
        if(err){
            return callback(err,null);
        }else {
            return callback(null, data);
        }
    });
}

auditTrailService.updateSoftRemoveAuditTrailById = function updateSoftRemoveAuditTrailById(auditId,callback){
    auditTrail.updateSoftRemoveAuditTrails(auditId,function(err,data){
        if(err){
            return callback(err,null);
        }else {
            return callback(null, data);
        }
    });
}

auditTrailService.removeAuditTrailById = function removeAuditTrailById(auditId,callback){
    auditTrail.removeAuditTrails({auditId:auditId},function(err,data){
        if(err){
            return callback(err,null);
        }else {
            return callback(null, data);
        }
    });
}

function toTimestamp(strDate){
    var datum = Date.parse(strDate);
    return datum/1000;
}

function checkServiceNowTicketState(state){
    var status = '';
    switch (parseInt(state)) {
        case 1:
            status = "New";
            break;
        case 2:
            status = "Opened";
            break;
        case 3:
            status = "In Progress";
            break;
        case 4:
            status = "Awaiting User Info";
            break;
        case 5:
            status = "Awaiting Evidence";
            break;
        case 6:
            status = "Resolved";
            break;
        case 7:
            status = "Closed";
            break;
        case 8:
            status = "Failed";
            break;
        default:
            status = "Failed";
            break;
    }
    return status;
}

function checkServiceNowTicketPriority(priority){
    var priorityState = '';
    switch (parseInt(priority)) {
        case 1:
            priorityState = "1-Critical";
            break;
        case 2:
            priorityState = "2-High";
            break;
        case 3:
            priorityState = "3-Moderate";
            break;
        case 4:
            priorityState = "4-Low";
            break;
        case 5:
            priorityState = "5-Planning";
            break;
        default:
            priorityState = "1-Critical";
            break;
    }
    return priorityState;
}
