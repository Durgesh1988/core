

var CronJob = {
    interval: '*/2 * * * *',
    getInterval: function() {
        return this.interval;
    },
    execute: function() {}
};

module.exports = CronJob;
