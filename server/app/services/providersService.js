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
// @TODO Move tag related functions to a different service
var logger = require('_pr/logger')(module);
var providersModel = require('_pr/model/providers/providers');
var awsProviderModel = require('_pr/model/providers/aws-provider');
var azureProviderModel = require('_pr/model/providers/azure-provider');
var vmWareProviderModel = require('_pr/model/providers/vmware-provider');
var openStackProviderModel = require('_pr/model/providers/openstack-provider');
var appConfig = require('_pr/config');
var Cryptography = require('_pr/lib/utils/cryptography');
var apiUtil = require('_pr/lib/utils/apiUtil.js');
var settingService = require('_pr/services/settingsService');
var async = require('async');
const errorType = 'provider';
var providersService = module.exports = {};

providersService.checkIfProviderExists = function checkIfProviderExists(providerId, callback) {
    providersModel.getProviderById(providerId, function(err, provider) {
        if(err) {
            var err = new Error('Internal server error');
            err.status = 500;
            return callback(err,null);
        } else if(!provider) {
            var err = new Error('Provider not found');
            err.status = 404;
            return callback(err,null);
        } else {
            return callback(null, provider);
        }
    });
};

providersService.getProvider = function getProvider(providerId, callback) {
    providersModel.getProviderById(providerId, function(err, provider) {
        if(err) {
            var err = new Error('Internal Server Error');
            err.status = 500;
            return callback(err,null);
        } else if (!provider) {
            var err = new Error('Provider not found');
            err.status = 404;
            return callback(err,null);
        } else if(provider) {
            providersService.createProviderResponseObject(provider,function(err,providerData){
                if(err){
                    var err = new Error('Internal Server Error');
                    err.status = 500;
                    return callback(err,null);
                }else{
                    return callback(null,providerData);
                }
            })
        }
    });
};

providersService.checkProviderAccess = function checkProviderAccess(orgs, providerId, callback) {
    providersService.getProvider(providerId, function(err, provider) {
        if(err) {
            return callback(err);
        }
        var authorized = orgs.reduce(function(a, b) {
            if(b == provider.orgId)
                return true || a;
            else
                return false || a;
        }, false);
        if(!authorized) {
            var err = new Error('Forbidden');
            err.status = 403;
            return callback(err,null);
        } else {
            return callback(null, provider);
        }
    });
};

providersService.createProvider = function createProvider(provider, callback) {
    switch(provider.type) {
        case 'aws':
            logger.debug('Creating new AWS provider');
            awsProviderModel.createNew(provider, function(err, provider) {
                if(err && err.name == 'ValidationError') {
                    var err = new Error('Bad Request');
                    err.status = 400;
                    callback(err,null);
                } else if(err) {
                    var err = new Error('Internal Server Error');
                    err.status = 500;
                    callback(err,null);
                }else {
                    callback(null, provider);
                }
            });
            break;
        case 'azure':
            logger.debug('Creating new AZURE provider');
            azureProviderModel.createNew(provider, function(err, provider) {
                if(err && err.name == 'ValidationError') {
                    var err = new Error('Bad Request');
                    err.status = 400;
                    callback(err,null);
                } else if(err) {
                    var err = new Error('Internal Server Error');
                    err.status = 500;
                    callback(err,null);
                }else {
                    callback(null, provider);
                }
            });
            break;
        case 'openStack':
            logger.debug('Creating new OpenStack provider');
            openStackProviderModel.createNew(provider, function(err, provider) {
                if(err && err.name == 'ValidationError') {
                    var err = new Error('Bad Request');
                    err.status = 400;
                    callback(err,null);
                } else if(err) {
                    var err = new Error('Internal Server Error');
                    err.status = 500;
                    callback(err,null);
                }else {
                    callback(null, provider);
                }
            });
            break;
        case 'vmWare':
            logger.debug('Creating new VMWare provider');
            vmWareProviderModel.createNew(provider, function(err, provider) {
                if(err && err.name == 'ValidationError') {
                    var err = new Error('Bad Request');
                    err.status = 400;
                    callback(err,null);
                } else if(err) {
                    var err = new Error('Internal Server Error');
                    err.status = 500;
                    callback(err,null);
                }else {
                    callback(null, provider);
                }
            });
            break;
        defaut:
            var err = new Error('Bad request');
            err.status = 400;
            return callback(err);
            break;
    }
};

providersService.updateProviderById = function updateProviderById(providerId, updateFields, callback) {
    var fields = {};
    if('name' in updateFields) {
        fields.name = updateFields.name;
    }
    var cryptoConfig = appConfig.cryptoSettings;
    var cryptography = new Cryptography(cryptoConfig.algorithm, cryptoConfig.password);
    switch (provider.type) {
        case 'aws':
            if ('providerDetails' in updateFields) {
                if ('accessKey' in updateFields.providerDetails) {
                    fields['providerDetails.accessKey'] = cryptography.encryptText(updateFields.providerDetails.accessKey, cryptoConfig.encryptionEncoding, cryptoConfig.decryptionEncoding);
                }
                if ('secretKey' in updateFields.providerDetails)
                    fields['providerDetails.secretKey'] = cryptography.encryptText(updateFields.providerDetails.secretKey, cryptoConfig.encryptionEncoding, cryptoConfig.decryptionEncoding);

                if ('s3BucketName' in updateFields.providerDetails)
                    fields['providerDetails.s3BucketName'] = updateFields.providerDetails.s3BucketName;

                if ('plannedCost' in updateFields.providerDetails)
                    fields['providerDetails.plannedCost'] = updateFields.providerDetails.plannedCost;

                if ('keyPairDetails' in updateFields.providerDetails)
                    fields['providerDetails.keyPairDetails'] = updateFields.providerDetails.keyPairDetails;
            }
            awsProviderModel.updateAWSProviderDetails(providerId, fields, function(err, result) {
                if(err || !result) {
                    var err = new Error('Internal Server Error');
                    err.status = 500;
                    return callback(err,null);
                } else if(result) {
                    return callback(null, result);
                }
            });
            break;
        case 'azure':
            if ('providerDetails' in updateFields) {
                if ('subscriptionId' in updateFields.providerDetails)
                    fields['providerDetails.subscriptionId'] = updateFields.providerDetails.subscriptionId;

                if ('clientId' in updateFields.providerDetails)
                    fields['providerDetails.clientId'] = updateFields.providerDetails.clientId;

                if ('clientSecret' in updateFields.providerDetails)
                    fields['providerDetails.clientSecret'] = updateFields.providerDetails.clientSecret;

                if ('tenant' in updateFields.providerDetails)
                    fields['providerDetails.tenant'] = updateFields.providerDetails.tenant;

                if ('pemFileId' in updateFields.providerDetails)
                    fields['providerDetails.pemFileId'] = updateFields.providerDetails.pemFileId;

                if ('keyFileId' in updateFields.providerDetails)
                    fields['providerDetails.keyFileId'] = updateFields.providerDetails.keyFileId;
            }
            azureProviderModel.updateAzureProviderDetails(providerId, fields, function(err, result) {
                if(err || !result) {
                    var err = new Error('Internal Server Error');
                    err.status = 500;
                    return callback(err,null);
                } else if(result) {
                    return callback(null, result);
                }
            });
            break;
        case 'openStack':
            if ('providerDetails' in updateFields) {
                if ('username' in updateFields.providerDetails)
                    fields['providerDetails.username'] = updateFields.providerDetails.username;

                if ('password' in updateFields.providerDetails)
                    fields['providerDetails.password'] = cryptography.encryptText(updateFields.providerDetails.password, cryptoConfig.encryptionEncoding, cryptoConfig.decryptionEncoding);

                if ('host' in updateFields.providerDetails)
                    fields['providerDetails.host'] = updateFields.providerDetails.host;

                if ('serviceEndPoints' in updateFields.providerDetails)
                    fields['providerDetails.serviceEndPoints'] = updateFields.providerDetails.serviceEndPoints;

                if ('tenantId' in updateFields.providerDetails)
                    fields['providerDetails.tenantId'] = updateFields.providerDetails.tenantId;

                if ('tenantName' in updateFields.providerDetails)
                    fields['providerDetails.tenantName'] = updateFields.providerDetails.tenantName;

                if ('keyName' in updateFields.providerDetails)
                    fields['providerDetails.keyName'] = updateFields.providerDetails.keyName;

                if ('projectName' in updateFields.providerDetails)
                    fields['providerDetails.projectName'] = updateFields.providerDetails.projectName;

                if ('pemFileId' in updateFields.providerDetails)
                    fields['providerDetails.pemFileId'] = updateFields.providerDetails.pemFileId;
            }
            openStackProviderModel.updateOpenStackProviderDetails(providerId, fields, function(err, result) {
                if(err || !result) {
                    var err = new Error('Internal Server Error');
                    err.status = 500;
                    return callback(err,null);
                } else if(result) {
                    return callback(null, result);
                }
            });
            break;
        case 'vmWare':
            if ('providerDetails' in updateFields) {
                if ('username' in updateFields.providerDetails)
                    fields['providerDetails.username'] = updateFields.providerDetails.username;

                if ('password' in updateFields.providerDetails)
                    fields['providerDetails.password'] = cryptography.encryptText(updateFields.providerDetails.password, cryptoConfig.encryptionEncoding, cryptoConfig.decryptionEncoding);

                if ('host' in updateFields.providerDetails)
                    fields['providerDetails.host'] = updateFields.providerDetails.host;

                if ('dc' in updateFields.providerDetails)
                    fields['providerDetails.dc'] = updateFields.providerDetails.dc;
            }
            vmWareProviderModel.updateVmWareProviderDetails(providerId, fields, function(err, result) {
                if(err || !result) {
                    var err = new Error('Internal Server Error');
                    err.status = 500;
                    return callback(err,null);
                } else if(result) {
                    return callback(null, result);
                }
            });
            break;
        default:
            var err = new Error('Bad request');
            err.status = 400;
            return callback(err);
            break;
    }
};

providersService.deleteProviderById = function deleteProviderById(providerId, callback) {
    providersModel.deleteProviderById(providerId, function(err, provider) {
        if(err) {
            var err = new Error('Internal server error');
            err.status = 500;
            return callback(err,null);
        } else if(!provider) {
            var err = new Error('Provider not found');
            err.status = 404;
            return callback(err,null);
        } else {
            return callback(null,true);
        }
    });
};

providersService.getAllProviders = function getAllProviders(reqQuery,userName, callback) {
    var reqObj = {};
    async.waterfall(
        [
            function (next) {
                apiUtil.changeRequestForJqueryPagination(reqQuery, next);
            },
            function (reqData, next) {
                reqObj = reqData;
                apiUtil.paginationRequest(reqData, 'providers', next);
            },
            function (paginationReq, next) {
                apiUtil.databaseUtil(paginationReq, next);
            },
            function (queryObj, next) {
                settingService.getOrgUserFilter(userName,function(err,orgIds){
                    if(err){
                        next(err,null);
                    }else if(orgIds.length > 0){
                        queryObj.queryObj['orgId'] = {$in:orgIds};
                        providersModel.getAllProviders(queryObj, next);
                    }else{
                        providersModel.getAllProviders(queryObj, next);
                    }
                });
            },
            function (providers, next) {
                providersService.createProviderResponseList(providers,next);
            },
            function (formattedScripts, next) {
                apiUtil.changeResponseForJqueryPagination(formattedScripts, reqObj, next);
            },

        ], function (err, results) {
            if (err){
                return callback(err,null);
            }else{
                return callback(null,results);
            }
        });
};

providersService.createProviderResponseObject = function createProviderResponseObject(provider, callback) {
    var providerResponseObject = {
        _id: provider._id,
        name: provider.name,
        type: provider.type,
        orgId: provider.orgId,
        invalidCredentials: provider.invalidCredentials,
        providerDetails: {}
    };
    switch(provider.type) {
        case 'aws':
            providerResponseObject.providerDetails.s3BucketName = provider.providerDetails.s3BucketName;
            providerResponseObject.providerDetails.lastBillUpdateTime = provider.providerDetails.lastBillUpdateTime;
            providerResponseObject.providerDetails.plannedCost = provider.providerDetails.plannedCost;
            providerResponseObject.providerDetails.keyPairDetails = provider.providerDetails.keyPairDetails;
            break;
        case 'azure':
            providerResponseObject.providerDetails.pemFileName = provider.providerDetails.pemFileName;
            providerResponseObject.providerDetails.keyFileName = provider.providerDetails.keyFileName;
            break;
        case 'openStack':
            providerResponseObject.providerDetails.serviceEndPoints = provider.providerDetails.serviceEndPoints;
            providerResponseObject.providerDetails.tenantId = provider.providerDetails.tenantId;
            providerResponseObject.providerDetails.tenantName = provider.providerDetails.tenantName;
            providerResponseObject.providerDetails.keyName = provider.providerDetails.keyName;
            providerResponseObject.providerDetails.projectName = provider.providerDetails.projectName;
            providerResponseObject.providerDetails.pemFileName = provider.providerDetails.pemFileName;
            break;
        case 'vmWare':
            providerResponseObject.providerDetails.host = provider.providerDetails.host;
            providerResponseObject.providerDetails.dc = provider.providerDetails.dc;
            break;
        default:
            var err = new Error('Bad request');
            err.status = 400;
            return callback(err,null);
            break;
    }
    callback(null, providerResponseObject);
};

providersService.createProviderResponseList = function createProviderResponseList(providers, callback) {
    var providersList = [];
    if(providers.docs.length == 0)
        return callback(null, providersList);
    for(var i = 0; i < providers.length; i++) {
        (function(provider) {
            providersService.createProviderResponseObject(provider, function(err, formattedProvider) {
                if(err) {
                    return callback(err,null);
                } else {
                    providersList.push(formattedProvider);
                }
                if(providersList.length == providers.docs.length) {
                    providers.docs = providersList;
                    return callback(null, providers);
                }
            });
        })(providers[i]);
    }
};
