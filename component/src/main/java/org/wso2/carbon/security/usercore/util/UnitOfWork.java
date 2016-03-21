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
import java.sql.SQLException;

/**
 * Support class to implement Unit of work patter.
 */
public class UnitOfWork implements AutoCloseable {

    private Connection connection;

    private UnitOfWork() throws SQLException {
        super();
    }

    /**
     * Begin the transaction process.
     * @param connection Database connection.
     * @return Instance of UnitOfWork.
     * @throws SQLException
     */
    public static UnitOfWork beginTransaction(Connection connection) throws SQLException {

        UnitOfWork unitOfWork = new UnitOfWork();
        unitOfWork.connection = connection;
        unitOfWork.connection.setAutoCommit(false);

        return unitOfWork;
    }

    public Connection getConnection() {
        return connection;
    }

    /**
     * Commit and close connection.
     * @throws SQLException
     */
    @Override
    public void close() throws SQLException {
        connection.commit();
        connection.close();
    }
}
