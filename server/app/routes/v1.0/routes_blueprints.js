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


// This file act as a Controller which contains blueprint related all end points.
var Blueprints = require('_pr/model/blueprint');
var usersDao = require('_pr/model/users.js');
var uuid = require('node-uuid');
var logger = require('_pr/logger')(module);
var errorResponses = require('./error_responses');
var fs = require('fs');
var blueprintServices = require('_pr/services/blueprintServices.js');

module.exports.setRoutes = function(app, sessionVerificationFunc) {
	app.all('/blueprints/*', sessionVerificationFunc);
	
	app.post('/blueprints', function(req, res) {
		var userDetails = {
			userName:req.session.user,
			category:'blueprints',
			action:'create',
			req:null,
			permissionSet:req.session.user.permissionset
		}
		blueprintServices.createNew(req.body.blueprintData,userDetails, function(err, blueprint) {
			if(err){
				res.status(err.errCode).send(err.errMessage);
			}
			res.status(200).send(blueprint);
		});
	});
	app.post('/blueprints/:blueprintId/update', function(req, res) {
		if (req.session.user.rolename === 'Consumer') {
			res.send(401);
			return;
		}
		var blueprintUpdateData = req.body.blueprintUpdateData;
		if (!blueprintUpdateData.runlist) {
			blueprintUpdateData.runlist = [];
		}
		blueprintServices.updateBlueprint(req.params.blueprintId,blueprintUpdateData, function(err, blueprint) {
			if(err){
				res.status(err.errCode).send(err.errMessage);
			}
			res.status(200).send(blueprint);
		});
	});

	app.delete('/blueprints/:blueprintId', function(req, res) {
		blueprintServices.removeBlueprintById(req.params.blueprintId, function(err, blueprint) {
			if(err){
				res.status(err.errCode).send(err.errMessage);
			}
			res.status(200).send(blueprint);
		});
	});

	app.get('/blueprints/:blueprintId/blueprintInfo', function(req, res) {
		blueprintServices.getBlueprintInfoById(req.params.blueprintId, function(err, blueprintInfo) {
			if(err){
				res.status(err.errCode).send(err.errMessage);
			}
			res.status(200).send(blueprintInfo);
		});
	});

	app.post('/blueprints/copy',function(req,res){
		var masterDetails = {
			orgId:req.body.orgId,
			orgName:req.body.orgName,
			bgId:req.body.bgId,
			bgName:req.body.bgName,
			projectId:req.body.projectId,
			projectName:req.body.projectName
		}
		blueprintServices.copyBlueprint(req.body.blueprintId,masterDetails, function(err, blueprint) {
			if(err){
				res.status(err.errCode).send(err.errMessage);
			}
			res.status(200).send(blueprint);
		});
	});


	app.get('/blueprints/:blueprintId/launch', function(req, res) {
		var userDetails = {
			userName:req.session.user,
			category:'blueprints',
			action:'execute',
			req:null,
			permissionSet:req.session.user.permissionset
		}
		var launchParams = {
			envId: req.query.envId,
			version: req.query.version,
			stackName: req.query.stackName,
			domainName:req.query.domainName,
			sessionUser: req.session.user.cn
		}
		blueprintServices.launchABlueprint(req.params.blueprintId,userDetails,launchParams,function(err,data){
			if(err){
				logger.error(err);
				res.send(401);
				return;
			}
			res.send(200);
			return;
		})
	});
    app.get('/blueprints/organization/:orgId/businessGroup/:bgId/project/:projectId/blueprintList', function(req, res) {
		var dataObj = {
			orgId : req.params.orgId,
			bgId : req.params.bgId,
			bgId : req.params.bgId,
			queryParams:req.query
		}
		blueprintServices.getBlueprintByOrgBgProject(dataObj, function(err, blueprints) {
			if(err){
				res.status(err.errCode).send(err.errMessage);
			}
			res.status(200).send(blueprints);
        });
    });
};