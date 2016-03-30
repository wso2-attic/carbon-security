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

package org.wso2.carbon.security.usercore.constant;

/**
 * Connector related constants.
 */
public class ConnectorConstants {

    public static final String DATA_SOURCE = "DataSource";
    public static final String DATABASE_TYPE = "DatabaseType";
    public static final String SQL_QUERIES = "SqlStatements";
    public static final String USERSTORE_ID = "UserstoreId";
    public static final java.lang.String USERSTORE_NAME = "UserstoreName";

    public static final class QueryTypes {

        public static final String SQL_QUERY_GET_GROUP_FROM_NAME = "sql_query_get_group_from_name";
        public static final String SQL_QUERY_GET_GROUP_FROM_ID = "sql_query_get_group_from_name";
        public static final String SQL_QUERY_COMPARE_PASSWORD_HASH = "sql_query_compare_password_hash";
        public static final String SQL_QUERY_GET_USER_FROM_ID = "sql_query_get_user_from_id";
        public static final String SQL_QUERY_GET_USER_FROM_USERNAME = "sql_query_get_user_from_username";
        public static final String SQL_QUERY_GET_USER_ATTRIBUTES = "sql_query_get_user_attributes";
        public static final String SQL_QUERY_GET_GROUPS_OF_USER = "sql_query_get_groups_of_user";
        public static final String SQL_QUERY_GET_USERS_OF_GROUP = "sql_query_get_users_of_group";
        public static final String SQL_QUERY_DELETE_USER = "sql_query_delete_user";
        public static final String SQL_QUERY_DELETE_GROUP = "sql_query_delete_group";
        public static final String SQL_QUERY_ADD_USER = "sql_query_add_user";
        public static final String SQL_QUERY_ADD_USER_CLAIMS = "sql_query_add_user_claims";
        public static final String SQL_QUERY_GET_GROUP_IDS = "sql_query_get_group_ids";
        public static final String SQL_QUERY_ADD_USER_GROUPS = "sql_query_add_user_groups";
        public static final String SQL_QUERY_GET_USER_IDS = "sql_query_get_user_ids";
        public static final String SQL_QUERY_ADD_GROUP = "sql_query_add_group";
        public static final String SQL_QUERY_LIST_USERS = "sql_query_list_users";
        public static final String SQL_QUERY_GET_GROUP_ID_FROM_UNIQUE_ID = "sql_query_get_group_id_from_unique_id";
        public static final String SQL_QUERY_GET_USER_ID_FROM_UNIQUE_ID = "sql_query_get_user_id_from_unique_id";
        public static final String SQL_QUERY_GET_PASSWORD_INFO = "sql_query_get_password_info";
        public static final String SQL_QUERY_ADD_PASSWORD_INFO = "sql_query_add_password_info";
        public static final String SQL_QUERY_UPDATE_CREDENTIAL = "sql_query_update_credential";
        public static final String SQL_QUERY_UPDATE_OLD_CREDENTIAL = "sql_query_update_old_credential";
        public static final String SQL_QUERY_SET_USER_ATTRIBUTE = "sql_query_set_user_attribute";
        public static final String SQL_QUERY_DELETE_USER_ATTRIBUTE = "sql_query_delete_user_attribute";
        public static final String SQL_QUERY_GET_USER_ATTRIBUTES_FROM_URI = "sql_query_get_user_attributes_from_uri";
    }
}
