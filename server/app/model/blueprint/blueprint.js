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
var mongoose = require('mongoose');
var extend = require('mongoose-schema-extend');
var ObjectId = require('mongoose').Types.ObjectId;
var mongoosePaginate = require('mongoose-paginate');
var schemaValidator = require('_pr/model/utils/schema-validator');
var Schema = mongoose.Schema;

var BlueprintSchema = new Schema({
    name: {
        type: String,
        required: true,
        trim: true,
        validate: schemaValidator.blueprintNameValidator
    },
    blueprintType: {
        type: String,
        required: true,
        trim: true
    },
    masterDetails: {
        orgId: {
            type: String,
            required: false,
            trim: true,
            validate: schemaValidator.orgIdValidator
        },
        orgName: {
            type: String,
            required: false,
            trim: true
        },
        bgId: {
            type: String,
            required: false,
            trim: true,
            validate: schemaValidator.bgIdValidator
        },
        bgName: {
            type: String,
            required: false,
            trim: true
        },
        projectId: {
            type: String,
            required: false,
            trim: true,
            validate: schemaValidator.projIdValidator
        },
        projectName: {
            type: String,
            required: false,
            trim: true
        }
    },
    providerDetails: {
        id: {
            type: String,
            required: false,
            trim: true
        },
        name: {
            type: String,
            required: false,
            trim: true
        },
        type: {
            type: String,
            required: false,
            trim: true
        }
    },
    imageDetails:{
        id: {
            type: String,
            required: false,
            trim: true
        },
        name: {
            type: String,
            required: false,
            trim: true
        }
    },
    serverDetails: {
        id: {
            type: String,
            required: false,
            trim: true
        },
        name: {
            type: String,
            required: false,
            trim: true
        },
        repoId: {
            type: String,
            required: false,
            trim: true
        },
        serverType:{
            type: String,
            required: false,
            trim: true
        },
        serverConfiguration:Schema.Types.Mixed
    },
    templateDetails: {
        id: {
            type: String,
            required: false,
            trim: true
        },
        name: {
            type: String,
            required: false,
            trim: true
        },
        type: {
            type: String,
            required: false,
            trim: true
        },
        iconPath: {
            type: String,
            trim: true,
            required: false
        }
    },
    blueprintConfig: Schema.Types.Mixed,
    version: {
        type: String,
        required: true,
        trim: true,
    },
    parentId: {
        type: String,
        required: false
    },
    domainNameCheck:{
        type:Boolean,
        required:false,
        default:false
    },
    shortDesc: {
        type: String,
        trim: true
    },
    botType: {
        type: String,
        trim: true,
    },
    isDeleted: {
        type: Boolean,
        default: false
    },
    createdOn: {
        type: String,
        default: Date.now
    }
});

BlueprintSchema.plugin(mongoosePaginate);

BlueprintSchema.statics.createNew = function(blueprintData, callback) {
    var blueprint = new Blueprints(blueprintData);
    blueprint.save(function(err, blueprint) {
        if (err) {
            logger.error(err);
            callback(err, null);
            return;
        }
        callback(null, blueprint);
    });
};


BlueprintSchema.statics.getById = function(id, callback) {
    this.findById(id, function(err, blueprint) {
        if (err) {
            callback(err, null);
            return;
        }
        callback(null, blueprint);
        return;
    });
};

BlueprintSchema.statics.getBlueprintById = function(blueprintId, callback) {
    this.find({_id: ObjectId(blueprintId)}, function(err, blueprint) {
        if (err) {
            callback(err, null);
            return;
        }
        callback(null, blueprint);
        return;
    });
};

BlueprintSchema.statics.getBlueprintByIds = function(blueprintIds, callback) {
    var ids = [];
    blueprintIds.forEach(function(v) {
        ids.push(ObjectId(v));
    });
    this.find({
        "_id": {
            $in: ids
        }
    }, function(err, blueprints) {
        if (err) {
            callback(err, null);
            return;
        }
        callback(null, blueprints);
        return;
    });
};

BlueprintSchema.statics.getCountByParentId = function(parentId, callback) {
    if (parentId) {
        this.find({
            $or: [{
                parentId: parentId
            }, {
                _id: ObjectId(parentId)
            }]
        }, function(err, blueprint) {
            if (err) {
                callback(err, null);
                return;
            } else {
                callback(null, blueprint.length);
                return;
            }
        });
    } else {
        callback(null, 0);
        return;
    }
};

BlueprintSchema.statics.getByIds = function(ids, callback) {
    this.find({
        "_id": {
            $in: ids
        }
    }, function(err, blueprints) {
        if (err) {
            callback(err, null);
            return;
        }
        callback(null, blueprints);
        return;
    });
};

BlueprintSchema.statics.removeById = function(id, callback) {
    this.remove({
        $or: [{
            "_id": ObjectId(id)
        }, {
            "parentId": id
        }]
    }, function(err, data) {
        if (err) {
            callback(err, null);
            return;
        }
        callback(null, data);
    });
};


BlueprintSchema.statics.getBlueprintsByOrgBgProject = function(jsonData, callback) {
    this.find(jsonData, function(err, blueprints) {
        if (err) {
            callback(err, null);
            return;
        }
        callback(null, blueprints);

    });
};

BlueprintSchema.statics.getBlueprintsByProviderId = function(providerId, callback) {
    this.find({
        "providerDetails.id": providerId
    },function(err, blueprints) {
        if (err) {
            logger.error(err);
            callback(err, null);
            return;
        }
        callback(null, blueprints);
    });
};
BlueprintSchema.statics.getBlueprintByOrgBgProjectProviderType = function(query, callback) {
    if(query.queryObj &&  query.options) {
        Blueprints.paginate(query.queryObj, query.options, function (err, blueprints) {
            if (err) {
                callback(err, null);
                return;
            }
            callback(null, blueprints);
        });
    }else{
        this.find(query,function(err, blueprints) {
            if (err) {
                logger.error(err);
                callback(err, null);
                return;
            }
            callback(null, blueprints);
        });
    }
};


BlueprintSchema.statics.checkBPDependencyByFieldName = function(fieldName,id, callback) {
    var queryObj = {};
    queryObj[fieldName] = id;
    Blueprints.find(queryObj, function(err, data) {
        if (err) {
            callback(err, null);
            return;
        }
        callback(null, data);
    });
};

var Blueprints = mongoose.model('blueprints', BlueprintSchema);

module.exports = Blueprints;
