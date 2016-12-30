(function (angular) {
    "use strict";
    angular.module('dashboard.analytics')
        .controller('discoveryResourcesCtrl', ['$scope', '$rootScope', '$state','analyticsServices', 'genericServices','$timeout','toastr','$modal', function ($scope,$rootScope,$state,analyticsServices,genSevs,$timeout,toastr,$modal){
            var disResrc=this;
            $scope.instanceType=null;
            $scope.selectInstanceRow=[];
            $scope.TagName={
                environment:[],
                bg:[],
                project:[] ,bgTag:'',
                environmentTag:'',
                projectTag:''
            };
            // get gat name  Start
            disResrc.getAllTagNames=function () {
                $scope.TagName={
                    environment:[],
                    bg:[],
                    project:[],
                    bgTag:'bg',
                    environmentTag:'env',
                    projectTag:'pro'
                };
                // environment
                var param = {
                    url: '/providers/' + fltrObj.provider.id + '/tag-mappings/environment'
                };
                genSevs.promiseGet(param).then(function (instResult) {
                    $scope.TagName.environmentTag=instResult.tagName+'-en';
                    angular.forEach(instResult.tagValues,function(val){
                        $scope.TagName.environment.push({id:val,name:val})
                    });
                });
                // Bu
                var param = {
                    url: '/providers/' + fltrObj.provider.id + '/tag-mappings/businessGroup'
                };
                genSevs.promiseGet(param).then(function (instResult) {
                    $scope.TagName.bgTag=instResult.tagName+'-bu';
                    angular.forEach(instResult.tagValues,function(val){
                        $scope.TagName.bg.push({id:val,name:val})
                    });
                });
                // project
                var param = {
                    url: '/providers/' + fltrObj.provider.id + '/tag-mappings/project'
                };
                genSevs.promiseGet(param).then(function (instResult) {
                    $scope.TagName.projectTag=instResult.tagName+'-pr';
                    angular.forEach(instResult.tagValues,function(val){
                        $scope.TagName.project.push({id:val,name:val})
                    });

                });

                // get gat name  End##########
            };
            disResrc.init=function () {
                if(fltrObj && fltrObj.provider && fltrObj.provider.id) {
                    disResrc.getAllTagNames();

                    $timeout(function () {
                        console.log( $scope.TagName);
                        disResrc.gridOptionInstances = {
                            allowCellFocus : false,
                            paginationPageSizes: [25, 50, 100],
                            paginationPageSize:25,
                            columnDefs: [],
                            onRegisterApi: function (gridApi) {
                                gridApi.edit.on.afterCellEdit($scope, function (rowEntity, colDef, newValue, oldValue) {
                                        var param = {
                                            url: '/providers/' + fltrObj.provider.id + '/unassigned-instances/' + rowEntity._id,
                                            data: {
                                                "tags": {
                                                    "environment": newValue,
                                                    "application": colDef.name.substring(0, colDef.name.length-3)
                                                }
                                            }
                                        };
                                    if(newValue !== oldValue) {
                                        genSevs.promisePatch(param).then(function () {
                                            toastr.success('Successfully updated.', 'Update');
                                        });
                                    }
                                });
                                gridApi.selection.on.rowSelectionChanged($scope,function(row){
                                    if(row.isSelected){
                                        $scope.selectInstanceRow.push(row.entity._id);
                                    } else {
                                        $scope.selectInstanceRow.splice(row.entity._id,1);
                                    }

                                });
                                gridApi.selection.on.rowSelectionChangedBatch($scope,function(rows){
                                    angular.forEach(rows,function(row){
                                        if(row.isSelected){
                                            $scope.selectInstanceRow.push(row.entity._id);
                                        } else {
                                            $scope.selectInstanceRow.splice(row.entity._id,1);
                                        }
                                    });
                                });
                            }
                        };
                        disResrc.gridOptionInstances.data = [];
                        if($rootScope.organNewEnt.instanceType === 'Managed') {
                            $scope.instanceType= 'managedInstances';
                        } else if($rootScope.organNewEnt.instanceType === 'Assigned'){
                            disResrc.gridOptionInstances.enableFiltering=true;
                            disResrc.gridOptionInstances.columnDefs=[
                                {name: 'InstanceId', field: 'platformId',enableCellEditOnFocus: false,
                                    enableCellEdit: false,enableFiltering: true},
                                {name: 'os', enableFiltering: true,displayName: 'OS', enableCellEdit: false, type: 'number',enableCellEditOnFocus: false},
                                {name: 'privateIpAddress',enableFiltering: true, displayName: 'IP Address',enableCellEditOnFocus: false,
                                    enableCellEdit: false},
                                {name: 'state',enableFiltering: true, displayName: 'Status',enableCellEditOnFocus: false,
                                    enableCellEdit: false},
                                {
                                    name: 'Region',enableFiltering: true,
                                    displayName: 'Region',
                                    field: 'providerData.region_name',
                                    cellTooltip: true,enableCellEditOnFocus: false,
                                    enableCellEdit: false
                                },
                                {name: 'orgName', enableFiltering: true,displayName: 'Org Name', field: 'orgName', cellTooltip: true,enableCellEditOnFocus: false,
                                    enableCellEdit: false},
                                {
                                    name: 'bgName',
                                    displayName: 'BG Name',enableFiltering: true,
                                    field: 'bgName', cellTooltip: true,enableCellEditOnFocus: false,
                                    enableCellEdit: false
                                },
                                {
                                    name: 'projectName',enableFiltering: true,
                                    displayName: 'Project Name',
                                    field: 'projectName', cellTooltip: true,enableCellEditOnFocus: false,
                                    enableCellEdit: false
                                },
                                {
                                    name: 'environmentName',enableFiltering: true,
                                    displayName: 'Env Name',
                                    field: 'environmentName', cellTooltip: true,enableCellEditOnFocus: false,
                                    enableCellEdit: false
                                }
                            ];
                            $scope.instanceType= 'unmanagedInstances';
                        } else if($rootScope.organNewEnt.instanceType === 'Unassigned'){
                            disResrc.gridOptionInstances.enableFiltering=false;
                            disResrc.gridOptionInstances.columnDefs= [
                                {name: 'InstanceId', field: 'platformId',enableCellEditOnFocus: false,
                                    enableCellEdit: false},
                                {name: 'os', displayName: 'OS', enableCellEdit: false, type: 'number',enableCellEditOnFocus: false},
                                {name: 'privateIpAddress', displayName: 'IP Address',enableCellEditOnFocus: false,
                                    enableCellEdit: false},
                                {name: 'state', displayName: 'Status',enableCellEditOnFocus: false,
                                    enableCellEdit: false},
                                {
                                    name: 'Region',
                                    displayName: 'Region',
                                    field: 'providerData.region_name',
                                    cellTooltip: true,enableCellEditOnFocus: false,
                                    enableCellEdit: false
                                },
                                {name: 'orgName', displayName: 'Org Name', field: 'orgName', cellTooltip: true,enableCellEditOnFocus: false,
                                    enableCellEdit: false},
                                {
                                    name: $scope.TagName.bgTag,
                                    displayName: 'BG Tag Value',
                                    width: 200,
                                    cellClass: 'editCell',
                                    enableCellEditOnFocus: true,
                                    enableCellEdit: true,
                                    editableCellTemplate: 'ui-grid/dropdownEditor',
                                    editDropdownOptionsArray: $scope.TagName.bg,
                                    editDropdownIdLabel: 'name',
                                    editDropdownValueLabel: 'id'
                                },
                                {
                                    name: $scope.TagName.projectTag,
                                    displayName: 'Project Tag Value',
                                    cellClass: 'editCell',
                                    width: 200,
                                    enableCellEditOnFocus: true,
                                    enableCellEdit: true,
                                    editableCellTemplate: 'ui-grid/dropdownEditor',
                                    editDropdownOptionsArray: $scope.TagName.project,
                                    editDropdownIdLabel: 'name',
                                    editDropdownValueLabel: 'id'
                                },
                                {
                                    name: $scope.TagName.environmentTag,
                                    displayName: 'Env Tag Value',
                                    cellClass: 'editCell',
                                    width: 200,
                                    enableCellEditOnFocus: true,
                                    enableCellEdit: true,
                                    editableCellTemplate: 'ui-grid/dropdownEditor',
                                    editDropdownOptionsArray: $scope.TagName.environment,
                                    editDropdownIdLabel: 'name',
                                    editDropdownValueLabel: 'id'
                                }
                            ];
                            $scope.instanceType= 'unassigned-instances';
                        }
                            var param = {
                                url: '/providers/' + fltrObj.provider.id + '/' + $scope.instanceType
                            };
                            genSevs.promiseGet(param).then(function (instResult) {
                                if($rootScope.organNewEnt.instanceType === 'Managed') {
                                    disResrc.gridOptionInstances.data = instResult.managedInstances;
                                } else if($rootScope.organNewEnt.instanceType === 'Assigned'){
                                    disResrc.gridOptionInstances.data = instResult.unmanagedInstances;
                                } else if($rootScope.organNewEnt.instanceType === 'Unassigned'){
                                    disResrc.gridOptionInstances.data = instResult.data;
                                }
                                disResrc.gridOptionInstances.isRowSelectable = function(row){
                                    if(row.entity.state !== 'running'){
                                        return false;
                                    } else {
                                        return true;
                                    }
                                };
                            });
                    }, 200);
                }
            };
            disResrc.importInstance =function ($event) {
                var modalInstance = $modal.open({
                    animation: true,
                    templateUrl: 'src/partials/sections/dashboard/analytics/view/instanceManage.html',
                    controller: 'instanceManageCtrl as insMang',
                    backdrop: 'static',
                    keyboard: false,
                    resolve: {
                        items: function() {
                            return  $scope.selectInstanceRow;
                        }
                    }
                });
                modalInstance.result.then(function() {

                }, function() {

                });
            };
            $rootScope.stateItems = $state.params;
            $rootScope.organNewEnt.provider='0';
            $rootScope.organNewEnt.instanceType='Unassigned';
            if($rootScope.organNewEnt.instanceType === 'Managed') {
                $scope.instanceType= 'unmanagedInstances';
            } else if($rootScope.organNewEnt.instanceType === 'Assigned'){
                $scope.instanceType= 'unmanagedInstances';
            } else if($rootScope.organNewEnt.instanceType === 'Unassigned'){
                $scope.instanceType= 'unassigned-instances';
            }
            analyticsServices.applyFilter(true,null);
            var treeNames = ['Cloud Management','Discovery','Resources'];
            $rootScope.$emit('treeNameUpdate', treeNames);
            var fltrObj=$rootScope.filterNewEnt;
            $rootScope.applyFilter =function(filterApp,period){
                analyticsServices.applyFilter(true,null);
                disResrc.init();
            };
            disResrc.init();
            
        }]).controller('instanceManageCtrl',['$scope','$rootScope','items','$modalInstance','genericServices',function ($scope,$rootScope,items,$modalInstance,genericServices) {
        $scope.items=items;
        $scope.IMGNewEnt={
            passType:'password',
            org:$rootScope.organObject[0]
        };
        //get configmanagement
        var params={
            url:'/organization/'+$scope.IMGNewEnt.org.orgid+'/configmanagement/list'
        }
        genericServices.promiseGet(params).then(function (list) {
            $scope.configOptions=list;
        });
        $scope.cancel = function() {
            $modalInstance.dismiss('cancel');
        };
    }]);
})(angular);