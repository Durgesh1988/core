

var logger = require('_pr/logger')(module);
var appConfig = require('_pr/config');
var commons=appConfig.constantData;

var ApiUtil = function() {

    this.checkEqual = function(x,y){
            if ( x === y ) {
                return true;
            }
            if ( ! ( x instanceof Object ) || ! ( y instanceof Object ) ) {
                return false;
            }
            if ( x.constructor !== y.constructor ) {
                return false;
            }
            for ( var p in x ) {
                if ( x.hasOwnProperty( p ) ) {
                    if ( ! y.hasOwnProperty( p ) ) {
                        return false;
                    }
                    if ( x[ p ] === y[ p ] ) {
                        continue;
                    }
                    if ( typeof( x[ p ] ) !== "object" ) {
                        return false;
                    }
                    if ( !this.checkEqual( x[ p ],  y[ p ] ) ) {
                        return false;
                    }
                }
            }
            for ( p in y ) {
                if ( y.hasOwnProperty( p ) && ! x.hasOwnProperty( p ) ) {
                    return false;
                }
            }
            return true;
    }
    this.paginationResponse=function(data,req, callback) {
        var response={};
        var sortField=req.mirrorSort;
        response[req.id]=data.docs;
        response['metaData']={
            totalRecords:data.total,
            pageSize:data.limit,
            page:data.page,
            totalPages:data.pages,
            sortBy:Object.keys(sortField)[0],
            sortOrder:req.mirrorSort ? (sortField[Object.keys(sortField)[0]]==1 ?'asc' :'desc') : '',
            filterBy:req.filterBy
        };
        callback(null, response);
        return;
    };

    this.databaseUtil=function(jsonData,callback){
        var queryObj={};
        var queryArr=[];
        var objAnd = {}
        var objOr=[];
        var databaseCall={};
        var fields=commons.sort_field;
        var sortField=jsonData.mirrorSort;
        var key=Object.keys(sortField)[0];

        if(fields.indexOf(key) !== -1){
            var sortBy = {};
            if(sortField[key] === -1){
                sortBy[commons.sortReferanceData[jsonData.id]] = 1;
            };
            if(sortField[key] === 1){
                sortBy[commons.sortReferanceData[jsonData.id]] = -1;
            }
            jsonData.sortBy=sortBy;
        }
        if(jsonData.search) {
            queryArr.push(objAnd);
            for(var i = 0; i < jsonData.searchColumns.length; i++){
                var searchParam={};
                searchParam[jsonData.searchColumns[i]]={
                  $regex: new RegExp(jsonData.search, "i")
                };
                objOr.push(searchParam);
            }
            queryArr.push({$or:objOr});
        }
        if(jsonData.filterBy) {
            objAnd = jsonData.filterBy;
        }
        queryArr.push(objAnd);
        queryObj['$and']=queryArr;
        var options = {
            sort: jsonData.sortBy,
            lean: false,
            page: jsonData.page > 0 ? jsonData.page : 1 ,
            limit: jsonData.pageSize
        };
        databaseCall['queryObj']=queryObj;
        databaseCall['options']=options;
        callback(null, databaseCall);
        return;
    };

    this.paginationRequest=function(data,key, callback) {
        var pageSize,page;
        if(data.pageSize) {
            pageSize = parseInt(data.pageSize);
            if (pageSize > commons.max_record_limit) {
                pageSize = commons.max_record_limit;
            }
        } else {
            pageSize = commons.record_limit;
        }
        if(data.page) {
            page = parseInt(data.page);
        } else {
            page = commons.skip_Records;
        }

        var sortBy={};
        if(data.sortBy) {
            sortBy[data.sortBy] = data.sortOrder == 'desc' ? -1 : 1;
        } else {
            sortBy[commons.sortReferanceData[key]] = commons.sort_order == 'desc' ? -1 : 1;
        }

        var request={
            'sortBy':sortBy,
            'mirrorSort' :sortBy,
            'page':page,
            'pageSize':pageSize,
            'id':key
        };
        var filterBy={};
        if(data.filterBy) {
            var a = data.filterBy.split(",");
            for (var i = 0; i < a.length; i++) {
                var b = a[i].split(":");
                var c = b[1].split("+");
                if (c.length > 1) {
                    filterBy[b[0]] = {'$in': c};
                } else {
                    filterBy[b[0]] = b[1];
                }
            }
            request['filterBy'] = filterBy;
        }
        if (data.instanceType) {
            filterBy['blueprintData.templateType'] = data.instanceType;
            request['filterBy']=filterBy;

        }
        if(data.search){
            request['search']=data.search;
        }
        if (typeof callback === 'function') {
            callback(null, request);
        }
    }

    this.queryFilterBy = function(query,callback){
        var filterByObj = {};
        if(query.filterBy) {
            var filters = query.filterBy.split(',');
            for (var i = 0; i < filters.length; i++) {
                var filter = filters[i].split(':');
                var filterQueryValues = filter[1].split("+");
                if (filterQueryValues.length > 1) {
                    filterByObj[filter[0]] = {'$in': filterQueryValues};
                } else {
                    filterByObj[filter[0]] = filter[1];
                }

            }
            callback(null, filterByObj);
        }else{
            callback(null, filterByObj);
        }
    }

}

module.exports = new ApiUtil();