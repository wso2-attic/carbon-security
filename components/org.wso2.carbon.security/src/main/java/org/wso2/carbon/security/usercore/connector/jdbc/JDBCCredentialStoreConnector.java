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
import org.wso2.carbon.security.usercore.connector.CredentialStoreConnector;
import org.wso2.carbon.security.usercore.constant.ConnectorConstants;
import org.wso2.carbon.security.usercore.constant.DatabaseColumnNames;
import org.wso2.carbon.security.usercore.constant.UserStoreConstants;
import org.wso2.carbon.security.usercore.exception.AuthenticationFailure;
import org.wso2.carbon.security.usercore.exception.CredentialStoreException;
import org.wso2.carbon.security.usercore.util.DatabaseUtil;
import org.wso2.carbon.security.usercore.util.NamedPreparedStatement;
import org.wso2.carbon.security.usercore.util.UnitOfWork;
import org.wso2.carbon.security.usercore.util.UserCoreUtil;

import java.security.NoSuchAlgorithmException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Map;
import java.util.Properties;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.sql.DataSource;

/**
 * JDBC connector for the credential store.
 */
public class JDBCCredentialStoreConnector implements CredentialStoreConnector {

    Logger log = LoggerFactory.getLogger(JDBCCredentialStoreConnector.class);

    private DataSource dataSource;
    private CredentialStoreConfig credentialStoreConfig;
    private Map<String, String> sqlQueries;
    private String credentialStoreId;

    public void init(CredentialStoreConfig configuration) throws CredentialStoreException {

        Properties properties = configuration.getStoreProperties();

        this.credentialStoreConfig = configuration;
        this.credentialStoreId = properties.getProperty(UserStoreConstants.USER_STORE_ID);
        this.sqlQueries = (Map<String, String>) properties.get(ConnectorConstants.SQL_QUERIES);
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

        if (username == null || password == null) {
            throw new AuthenticationFailure("Username or password is null");
        }

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement getPasswordInfoPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_PASSWORD_INFO));
            getPasswordInfoPreparedStatement.setString("username", username);

            ResultSet resultSet = getPasswordInfoPreparedStatement.getPreparedStatement().executeQuery();
            if (!resultSet.next()) {
                throw new CredentialStoreException("Unable to retrieve password information.");
            }

            String hashAlgo = resultSet.getString(DatabaseColumnNames.PasswordInfo.HASH_ALGO);
            String salt = resultSet.getString(DatabaseColumnNames.PasswordInfo.PASSWORD_SALT);

            NamedPreparedStatement comparePasswordPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_COMPARE_PASSWORD_HASH));

            String hashedPassword = UserCoreUtil.hashPassword(password, salt, hashAlgo);
            comparePasswordPreparedStatement.setString("hashed_password", hashedPassword);
            comparePasswordPreparedStatement.setString("username", username);

            resultSet = comparePasswordPreparedStatement.getPreparedStatement().executeQuery();
            if (!resultSet.next()) {
                throw new AuthenticationFailure("Invalid username or password");
            }

            return resultSet.getString(DatabaseColumnNames.User.USER_UNIQUE_ID);
        } catch (SQLException | NoSuchAlgorithmException e) {
            throw new CredentialStoreException("Exception occurred while authenticating the user", e);
        }
    }

    @Override
    public void updateCredential(String username, Object newCredential) throws CredentialStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement getPasswordInfoPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_PASSWORD_INFO));
            getPasswordInfoPreparedStatement.setString("username", username);

            ResultSet resultSet = getPasswordInfoPreparedStatement.getPreparedStatement().executeQuery();
            if (!resultSet.next()) {
                throw new CredentialStoreException("Unable to retrieve password information.");
            }

            String hashAlgo = resultSet.getString(DatabaseColumnNames.PasswordInfo.HASH_ALGO);
            String salt = resultSet.getString(DatabaseColumnNames.PasswordInfo.PASSWORD_SALT);

            String hashedPassword = UserCoreUtil.hashPassword((char []) newCredential, salt, hashAlgo);

            NamedPreparedStatement updateCredentialPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_UPDATE_CREDENTIAL));
            updateCredentialPreparedStatement.setString("username", username);
            updateCredentialPreparedStatement.setString("credential", hashedPassword);
            int rowCount = updateCredentialPreparedStatement.getPreparedStatement().executeUpdate();

            if (rowCount < 1) {
                throw new CredentialStoreException("No credentials updated.");
            }
        } catch (SQLException | NoSuchAlgorithmException e) {
            throw new CredentialStoreException("Error occurred while updating credentials.", e);
        }
    }

    @Override
    public boolean canHandle(Callback[] callbacks) {

        boolean nameCallbackPresent = false;
        boolean passwordCallbackPresent = false;

        for (Callback callback : callbacks) {
            if (callback instanceof  NameCallback) {
                nameCallbackPresent = true;
            }
            if (callback instanceof  PasswordCallback) {
                passwordCallbackPresent = true;
            }
        }

        return nameCallbackPresent && passwordCallbackPresent;
    }
}
