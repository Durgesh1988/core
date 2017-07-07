

"use strict"
var fs = require('fs')
var cronTab = require('node-crontab');
var logger = require('_pr/logger')(module);
var incidentSync = require('_pr/cronjobs/incident-sync');

module.exports.start = function start() {

	logger.info('Incident Sync started with interval ==> '+ incidentSync.getInterval());
	var incidentSyncJobId
		= cronTab.scheduleJob(incidentSync.getInterval(), incidentSync.execute);

}