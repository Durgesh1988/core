
var logger = require('_pr/logger')(module);
var express = require("express");
var path = require("path");

module.exports.setRoutes = function(app) {

    app.use(errorHandler);

    function errorHandler(err, req, res, next) {
        if(err) {
            logger.error(err);

            var errorResponse = {
                'status': err.status,
                'message': err.message,
                'errors': []
            };
            if ('errors' in err) {
                for(var i = 0; i < err.errors.length; i++) {
                    if('messages' in err.errors[i])
                        errorResponse.errors.push(err.errors[i].messages);
                }
            }
            return res.status(err.status).send(errorResponse);
        }
    }
}
