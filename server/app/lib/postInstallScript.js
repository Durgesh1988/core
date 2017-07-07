var os = require('os');
var childProcess = require('child_process');
var fs = require('fs');
console.log('Running post installation script');
var shortLinkPath = __dirname + '/../../node_modules/_pr';
var osName = os.type();
fs.unlink(shortLinkPath, function(err) {
    console.log('Creating short links');
    var cmd = 'ln -s ../app ' + shortLinkPath;
    if (osName === 'Windows') {
        cmd = 'mklink /D ' + shortLinkPath + ' ..\\app';
    }
    childProcess.exec(cmd, {
    }, function(err, stdout, stderr) {
        if (err) {
            throw err;
            return;
        }
        console.log('post installation script ran successfully');
    });
});