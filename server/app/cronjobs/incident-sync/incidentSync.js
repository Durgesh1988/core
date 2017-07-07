
var logger = require('_pr/logger')(module);
var CatalystCronJob = require('_pr/cronjobs/CatalystCronJob');
var async = require('async');
var IncidentSync = Object.create(CatalystCronJob);
IncidentSync.interval = '*/2 * * * *';
IncidentSync.execute = incidentSync;

module.exports = IncidentSync;

function incidentSync(){

}





