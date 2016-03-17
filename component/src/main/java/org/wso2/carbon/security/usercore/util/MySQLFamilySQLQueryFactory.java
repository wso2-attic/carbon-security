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
            "WHERE USERNAME = :username AND PASSWORD = :hashedPassword";

    private static final String GET_USER_FROM_USERNAME =
            "SELECT USER_UNIQUE_ID " +
            "FROM UM_USER " +
            "WHERE USERNAME = :username";

    private static final String GET_USER_FROM_ID =
            "SELECT USERNAME " +
            "FROM UM_USER " +
            "WHERE USER_UNIQUE_ID = :userId";

    private static final String GET_GROUP_FROM_NAME =
            "SELECT GROUP_UNIQUE_ID " +
            "FROM UM_GROUP " +
            "WHERE GROUP_NAME = :groupName";

    private static final String GET_GROUP_FROM_ID =
            "SELECT GROUP_NAME " +
            "FROM UM_GROUP " +
            "WHERE GROUP_UNIQUE_ID = :groupId";

    private static final String GET_USER_ATTRIBUTES =
            "SELECT ATTR_NAME, ATTR_VALUE " +
            "FROM UM_USER_ATTRIBUTES " +
            "WHERE USER_ID = (SELECT USER_ID FROM UM_USER WHERE USER_UNIQUE_ID = :userId)";

    private static final String DELETE_USER =
            "DELETE FROM UM_USER " +
            "WHERE USER_UNIQUE_ID = :userId";

    private static final String DELETE_GROUP =
            "DELETE FROM UM_GROUP " +
            "WHERE GROUP_UNIQUE_ID = :groupId";

    public MySQLFamilySQLQueryFactory() {

        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_COMPARE_PASSWORD_HASH, COMPARE_PASSWORD_HASH);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_USER_FROM_USERNAME, GET_USER_FROM_USERNAME);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_USER_FROM_ID, GET_USER_FROM_ID);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_GROUP_FROM_NAME, GET_GROUP_FROM_NAME);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_GROUP_FROM_ID, GET_GROUP_FROM_ID);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_USER_ATTRIBUTES, GET_USER_ATTRIBUTES);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_USER, DELETE_USER);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_GROUP, DELETE_GROUP);
    }
}
