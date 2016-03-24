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

package org.wso2.carbon.security.usercore.util;

import org.wso2.carbon.security.usercore.constant.ConnectorConstants;

/**
 * SQL queries for MySQL family based databases.
 */
public class MySQLFamilySQLQueryFactory extends SQLQueryFactory {

    private static final String COMPARE_PASSWORD_HASH =
            "SELECT USER_UNIQUE_ID " +
            "FROM UM_USER " +
            "WHERE USERNAME = :username; AND PASSWORD = :hashed_password;";

    private static final String GET_USER_FROM_USERNAME =
            "SELECT USER_UNIQUE_ID " +
            "FROM UM_USER " +
            "WHERE USERNAME = :username;";

    private static final String GET_USER_FROM_ID =
            "SELECT USERNAME " +
            "FROM UM_USER " +
            "WHERE USER_UNIQUE_ID = :user_id;";

    private static final String GET_GROUP_FROM_NAME =
            "SELECT GROUP_UNIQUE_ID " +
            "FROM UM_GROUP " +
            "WHERE GROUP_NAME = :groupname;";

    private static final String GET_GROUP_FROM_ID =
            "SELECT GROUP_NAME " +
            "FROM UM_GROUP " +
            "WHERE GROUP_UNIQUE_ID = :group_id;";

    private static final String GET_USER_ATTRIBUTES =
            "SELECT ATTR_NAME, ATTR_VALUE " +
            "FROM UM_USER_ATTRIBUTES " +
            "WHERE USER_ID = (SELECT USER_ID " +
                             "FROM UM_USER " +
                             "WHERE USER_UNIQUE_ID = :user_id;)";

    private static final String DELETE_USER =
            "DELETE FROM UM_USER " +
            "WHERE USER_UNIQUE_ID = :userId;";

    private static final String DELETE_GROUP =
            "DELETE FROM UM_GROUP " +
            "WHERE GROUP_UNIQUE_ID = :groupId;";

    private static final String GET_GROUP_IDS =
            "SELECT ID " +
            "FROM UM_GROUP " +
            "WHERE GROUP_NAME IN (:groupnames;)";

    private static final String ADD_USER =
            "INSERT INTO UM_USER (USER_UNIQUE_ID, USERNAME, PASSWORD) " +
            "VALUES (:user_unique_id;, :username;, :password;)";

    private static final String ADD_USER_ATTRIBUTES =
            "INSERT INTO UM_USER_ATTRIBUTES (ATTR_NAME, ATTR_VALUE, USER_ID) " +
            "VALUES (:attr_name;, :attr_val;, :user_id;)";

    private static final String ADD_USER_GROUPS =
            "INSERT INTO UM_USER_GROUP (USER_ID, GROUP_ID) " +
            "VALUES (:user_id;, :group_id;)";

    private static final String GET_USER_IDS =
            "SELECT ID " +
            "FROM UM_USER " +
            "WHERE USERNAME IN (:usernames;)";

    private static final String ADD_GROUP =
            "INSERT INTO (GROUP_NAME, GROUP_UNIQUE_ID) " +
            "VALUES (:group_name;, :group_id;)";

    private static final String LIST_USERS =
            "SELECT USERNAME " +
            "FROM UM_USER " +
            "WHERE USERNAME LIKE :username;" +
            "LIMIT :length;" +
            "OFFSET :offset;";

    public static final String GET_GROUPS_OF_USER =
            "SELECT GROUP_NAME, GROUP_UNIQUE_ID " +
            "FROM UM_GROUP " +
            "WHERE ID = (SELECT GROUP_ID " +
                        "FROM UM_USER_GROUP " +
                        "WHERE USER_ID = :user_id;)";

    public static final String GET_USERS_OF_GROUP =
            "SELECT USERNAME, USER_UNIQUE_ID " +
            "FROM UM_USER " +
            "WHERE ID = (SELECT USER_ID " +
                        "FROM UM_USER_GROUP " +
                        "WHERE GROUP_ID = :group_id;)";

    public static final String GET_PASSWORD_INFO =
            "SELECT PASSWORD_SALT, HASH_ALGO " +
            "FROM UM_PASSWORD_INFO " +
            "WHERE USER_ID = (SELECT ID " +
                             "FROM UM_USER " +
                             "WHERE USERNAME = :username;)";

    public static final String ADD_PASSWORD_INFO =
            "INSERT INTO UM_PASSWORD_INFO (USER_ID, PASSWORD_SALT, HASH_ALGO) " +
            "VALUES (:user_id;, :password_salt;, :hash_algo;)";

    public MySQLFamilySQLQueryFactory() {

        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_COMPARE_PASSWORD_HASH, COMPARE_PASSWORD_HASH);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_USER_FROM_USERNAME, GET_USER_FROM_USERNAME);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_USER_FROM_ID, GET_USER_FROM_ID);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_GROUP_FROM_NAME, GET_GROUP_FROM_NAME);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_GROUP_FROM_ID, GET_GROUP_FROM_ID);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_USER_ATTRIBUTES, GET_USER_ATTRIBUTES);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_USER, DELETE_USER);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_GROUP, DELETE_GROUP);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_GROUP_IDS, GET_GROUP_IDS);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_USER, ADD_USER);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_USER_CLAIMS, ADD_USER_ATTRIBUTES);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_USER_GROUPS, ADD_USER_GROUPS);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_USER_IDS, GET_USER_IDS);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_GROUP, ADD_GROUP);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_LIST_USERS, LIST_USERS);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_GROUPS_OF_USER, GET_GROUPS_OF_USER);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_USERS_OF_GROUP, GET_USERS_OF_GROUP);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_PASSWORD_INFO, GET_PASSWORD_INFO);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_PASSWORD_INFO, ADD_PASSWORD_INFO);
    }
}
