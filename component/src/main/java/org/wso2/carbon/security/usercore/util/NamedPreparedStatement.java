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

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * Prepared statement with named indexes.
 */
public class NamedPreparedStatement {

    private PreparedStatement preparedStatement;
    private List<String> fields = new ArrayList<>();

    public NamedPreparedStatement(Connection connection, String sqlQuery) throws SQLException {

        int pos;
        while ((pos = sqlQuery.indexOf(":")) != -1) {
            int end = sqlQuery.substring(pos).indexOf(" ");
            if (end == -1) {
                end = sqlQuery.length();
            }
            else {
                end += pos;
            }
            fields.add(sqlQuery.substring(pos + 1,end));
            sqlQuery = sqlQuery.substring(0, pos) + "?" + sqlQuery.substring(end);
        }
        preparedStatement = connection.prepareStatement(sqlQuery);
    }

    public PreparedStatement getPreparedStatement() {
        return preparedStatement;
    }

    public void setLong(String name, long value) throws SQLException {
        preparedStatement.setLong(getIndex(name), value);
    }

    public void setInt(String name, int value) throws SQLException {
        preparedStatement.setInt(getIndex(name), value);
    }

    public void setString(String name, String value) throws SQLException {
        preparedStatement.setString(getIndex(name), value);
    }

    private int getIndex(String name) {
        return fields.indexOf(name) + 1;
    }
}
