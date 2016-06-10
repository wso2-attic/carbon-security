/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.security.caas.user.core.constant;

/**
 * Names of the caches.
 */
public class CacheNames {

    // Identity store related.
    public static final String USER_USERNAME = "user-username";
    public static final String USER_USERID = "user-userid";
    public static final String GROUP_GROUPNAME = "group-groupname";
    public static final String GROUP_GROUPID = "group-groupid";
    public static final String GROUPS_USERID_IDENTITYSTOREID = "groups-userid-identitystoreid";

    // Authorization store related.
    public static final String ROLE_ROLENAME = "role-rolename";
    public static final String ROLES_USERID_IDENTITYSTOREID = "roles-userid-identitystoreid";
    public static final String ROLES_GROUPID_IDENTITYSTOREID = "roles-groupid-identitystoreid";
    public static final String PERMISSION_REOURCEID_ACTION = "permission-resourceid-action";
    public static final String PERMISSIONS_ROLEID_AUTHORIZATIONSTOREID = "permissions-roleid-authorizationstoreid";
}
