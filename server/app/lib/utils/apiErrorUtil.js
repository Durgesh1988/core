

var apiErrorUtil = module.exports = {};

apiErrorUtil.malformedRequest = function malformedRequest(fields) {
    this.status = 400;
    this.message = "Malformed request";
    this.fields = fields;
};
apiErrorUtil.unauthorizedRequest = function unauthorizedRequest(fields) {
    this.status = 401;
    this.message = "Unauthorized request";
    this.fields = fields;
};
apiErrorUtil.forbidden = function forbidden(fields) {
    this.status = 403;
    this.message = "Forbidden";
    this.fields = fields;
};
apiErrorUtil.notFound = function notFound(fields) {
    this.status = 404;
    this.message = "Not found";
    this.fields = fields;
};
apiErrorUtil.unexpectedContentType = function unexpectedContentType(fields) {
    this.status = 406;
    this.message = "Unexpected content type";
    this.fields = fields;
};
apiErrorUtil.conflict = function conflict(fields) {
    this.status = 409;
    this.message = "Conflict needs to be resolved";
    this.fields = fields;
};
apiErrorUtil.invalidRequest = function invalidRequest(fields) {
    this.status = 422;
    this.message = "Invalid Request";
    this.fields = fields;
};
apiErrorUtil.internalServerError = function internalServerError(fields) {
    this.status = 500;
    this.message = "Invalid Server Error";
    this.fields = fields;
};
