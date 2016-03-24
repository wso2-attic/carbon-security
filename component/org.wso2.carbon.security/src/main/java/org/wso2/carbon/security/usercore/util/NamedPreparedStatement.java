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

    /**
     * Create a named prepared statement with repeated indexes.
     * @param connection Database connection to be used.
     * @param sqlQuery Underlying SQL query.
     * @param repetition Repetition of each index.
     * @throws SQLException
     */
    public NamedPreparedStatement(Connection connection, String sqlQuery, int repetition) throws SQLException {

        int pos;
        while ((pos = sqlQuery.indexOf(":")) != -1) {

            int end = sqlQuery.substring(pos).indexOf(";");
            if (end == -1) {
                end = sqlQuery.length();
            }
            else {
                end += pos;
            }

            fields.add(sqlQuery.substring(pos + 1, end));

            StringBuilder builder = new StringBuilder("?");
            for (int i = 0; i < repetition - 1; i++) {
                builder.append(", ?");
            }
            sqlQuery = sqlQuery.substring(0, pos) + builder.toString() + sqlQuery.substring(end + 1);
        }
        preparedStatement = connection.prepareStatement(sqlQuery);
    }

    /**
     * Create a named prepared statement.
     * @param connection Database connection to be used.
     * @param sqlQuery Underlying SQL query.
     * @throws SQLException
     */
    public NamedPreparedStatement(Connection connection, String sqlQuery) throws SQLException {
        this(connection, sqlQuery, 0);
    }

    /**
     * Get underlying prepared statement.
     * @return @see PreparedStatement.
     */
    public PreparedStatement getPreparedStatement() {
        return preparedStatement;
    }

    /**
     * Set <code>long</code> value for the named index.
     * @param name Name of the index.
     * @param value Value to be replaced.
     * @throws SQLException
     */
    public void setLong(String name, long value) throws SQLException {
        preparedStatement.setLong(getIndex(name), value);
    }

    /**
     * Set <code>int</code> value for the named index.
     * @param name Name of the index.
     * @param value Value to be replaced.
     * @throws SQLException
     */
    public void setInt(String name, int value) throws SQLException {
        preparedStatement.setInt(getIndex(name), value);
    }

    /**
     * Set <code>String</code> value for the named index.
     * @param name Name of the index.
     * @param value Value to be replaced.
     * @throws SQLException
     */
    public void setString(String name, String value) throws SQLException {
        preparedStatement.setString(getIndex(name), value);
    }

    /**
     * Replace repeated indexes with the list of values.
     * @param name Name of the index.
     * @param values Values to be replaced.
     * @throws SQLException
     */
    public void setString(String name, List<String> values) throws SQLException {

        int indexInc = 0;
        for (String value : values) {
            preparedStatement.setString(getIndex(name) + indexInc, value);
            indexInc++;
        }
    }

    private int getIndex(String name) {
        return fields.indexOf(name) + 1;
    }
}
