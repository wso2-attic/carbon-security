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

package org.wso2.carbon.security.usercore.connector.jdbc;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.datasource.core.exception.DataSourceException;
import org.wso2.carbon.security.internal.config.CredentialStoreConfig;
import org.wso2.carbon.security.usercore.connector.ConnectorConstants;
import org.wso2.carbon.security.usercore.connector.CredentialStoreConnector;
import org.wso2.carbon.security.usercore.exception.AuthenticationFailure;
import org.wso2.carbon.security.usercore.exception.CredentialStoreException;
import org.wso2.carbon.security.usercore.util.DatabaseUtil;
import org.wso2.carbon.security.usercore.util.NamedPreparedStatement;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Map;
import java.util.Properties;

/**
 * JDBC connector for the credential store.
 */
public class JDBCCredentialStoreConnector implements CredentialStoreConnector {

    Logger log = LoggerFactory.getLogger(JDBCCredentialStoreConnector.class);

    private DataSource dataSource;
    private CredentialStoreConfig identityStoreConfig;
    private Map<String, String> sqlQueries;
    private String credentialStoreId;

    public void init(CredentialStoreConfig configuration) throws CredentialStoreException {

        Properties properties = configuration.getStoreProperties();

        this.identityStoreConfig = configuration;
        this.sqlQueries = (Map<String, String>) properties.get(ConnectorConstants.SQL_STATEMENTS);
        try {
            this.dataSource = DatabaseUtil.getInstance().getDataSource(properties
                    .getProperty(ConnectorConstants.DATA_SOURCE));
        } catch (DataSourceException e) {
            throw new CredentialStoreException("Error while setting the data source", e);
        }
    }

    @Override
    public String getCredentialStoreId() {
        return credentialStoreId;
    }

    @Override
    public String authenticate(Callback[] callbacks) throws CredentialStoreException, AuthenticationFailure {

        String username = null;
        char [] password = null;

        for (Callback callback : callbacks) {
            if (callback instanceof NameCallback) {
                username = ((NameCallback) callback).getName();
            } else if (callback instanceof PasswordCallback) {
                password = ((PasswordCallback) callback).getPassword();
            }
        }

        // TODO: Use StringUtils here if possible.
        if (username == null || password == null) {
            throw new AuthenticationFailure("Username or password is null");
        }

        Connection connection = null;
        try {
            connection = dataSource.getConnection();
            NamedPreparedStatement preparedStatement = new NamedPreparedStatement(connection,
                    sqlQueries.get(ConnectorConstants.SQL_QUERY_GET_USER_PASSWORD));
            ResultSet resultSet = preparedStatement.executeQuery();
            if (!resultSet.next()) {
                throw new AuthenticationFailure("No user for given username");
            }

            String userId = resultSet.getString(DatabaseColumnNames.User.USER_ID);
            String dbPasswordHash = resultSet.getString(DatabaseColumnNames.User.PASSWORD);
            // TODO: Use correct hashing algorithm.
            String hashedPassword = hashPassword(password, null);

            // TODO: Use StringUtils here.
            if (!hashedPassword.equals(dbPasswordHash)) {
                throw new AuthenticationFailure("Password mismatch");
            } else {
                return userId;
            }
        } catch (SQLException e) {
            throw new CredentialStoreException("Exception occurred while authenticating the user", e);
        } finally {
            if (connection != null) {
                try {
                    connection.close();
                } catch (SQLException e) {
                    throw new CredentialStoreException("Error occurred while closing the connection", e);
                }
            }
        }
    }

    @Override
    public boolean canHandle(Callback[] callbacks) {
        return false;
    }

    private String hashPassword(char[] password, String hashAlgo) {

        // TODO: Implement this method.
        return new String(password);
    }
}
