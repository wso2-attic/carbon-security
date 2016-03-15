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

import org.wso2.carbon.datasource.core.exception.DataSourceException;
import org.wso2.carbon.security.usercore.bean.Group;
import org.wso2.carbon.security.usercore.bean.User;
import org.wso2.carbon.security.internal.config.IdentityStoreConfig;
import org.wso2.carbon.security.usercore.connector.ConnectorConstants;
import org.wso2.carbon.security.usercore.connector.IdentityStoreConnector;
import org.wso2.carbon.security.usercore.exception.IdentityStoreException;
import org.wso2.carbon.security.usercore.util.DatabaseUtil;
import org.wso2.carbon.security.usercore.util.NamedPreparedStatement;

import javax.naming.NamingException;
import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

/**
 * Identity store connector for JDBC based stores.
 */
public class JDBCIdentityStoreConnector implements IdentityStoreConnector {

    private DataSource dataSource;
    private IdentityStoreConfig identityStoreConfig;
    private Map<String, String> sqlStatements;
    private String userStoreId;

    @Override
    public void init(IdentityStoreConfig identityStoreConfig) throws IdentityStoreException {

        Properties properties = identityStoreConfig.getStoreProperties();

        this.sqlStatements = (Map<String, String>) properties.get(ConnectorConstants.SQL_STATEMENTS);
        this.userStoreId = properties.getProperty(ConnectorConstants.USERSTORE_ID);
        this.identityStoreConfig = identityStoreConfig;
        try {
            dataSource = DatabaseUtil.getInstance()
                    .getDataSource(properties.getProperty(ConnectorConstants.DATA_SOURCE));
        } catch (DataSourceException e) {
            e.printStackTrace();
        }
    }

    @Override
    public String getUserStoreName() {
        return null;
    }

    @Override
    public String getUserStoreID() {
        return null;
    }

    @Override
    public User getUser(String userID) throws IdentityStoreException {
        return null;
    }

    @Override
    public User getUserByName(String username) throws IdentityStoreException {
        return null;
    }

    @Override
    public List<User> listUsers(String filterPattern, int offset, int length) throws IdentityStoreException {
        return null;
    }

    @Override
    public Map<String, String> getUserClaimValues(String userID) throws IdentityStoreException {
        return null;
    }

    @Override
    public Map<String, String> getUserClaimValues(String userID, Set<String> claimURIs) throws IdentityStoreException {
        return null;
    }

    @Override
    public Group getGroupById(String groupId) throws IdentityStoreException {

        Connection connection = null;
        try {
            connection = dataSource.getConnection();
            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(connection,
                    sqlStatements.get(ConnectorConstants.SQL_QUERY_GET_GROUP));
            namedPreparedStatement.setString(DatabaseColumnNames.Group.GROUP_UNIQUE_ID, groupId);
            ResultSet resultSet = namedPreparedStatement.executeQuery();

            if (!resultSet.next()) {
                throw new IdentityStoreException("No group for given id");
            }
            String groupName = resultSet.getString(DatabaseColumnNames.Group.GROUP_NAME);
            return new Group(groupId, userStoreId, groupName);
        } catch (SQLException e) {
            throw new IdentityStoreException("Internal error occurred while communicating with database",e);
        } finally {
            if (connection != null) {
                try {
                    connection.close();
                } catch (SQLException e) {
                    throw new IdentityStoreException(e);
                }
            }
        }
    }

    @Override
    public Group getGroup(String groupName) throws IdentityStoreException {

        Connection connection = null;
        try {
            connection = dataSource.getConnection();
            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(connection,
                    sqlStatements.get(ConnectorConstants.SQL_QUERY_GET_GROUP));
            namedPreparedStatement.setString(DatabaseColumnNames.Group.GROUP_NAME, groupName);
            ResultSet resultSet = namedPreparedStatement.executeQuery();

            if (!resultSet.next()) {
                throw new IdentityStoreException("No group for given name");
            }
            String groupId = resultSet.getString(DatabaseColumnNames.Group.GROUP_UNIQUE_ID);
            return new Group(groupId, userStoreId, groupName);
        } catch (SQLException e) {
            throw new IdentityStoreException("Internal error occurred while communicating with database",e);
        } finally {
            if (connection != null) {
                try {
                    connection.close();
                } catch (SQLException e) {
                    throw new IdentityStoreException(e);
                }
            }
        }
    }

    @Override
    public List<Group> listGroups(String attribute, String filter, int maxItemLimit) throws IdentityStoreException {
        return null;
    }

    @Override
    public List<Group> getGroupsOfUser(String userID) throws IdentityStoreException {
        return null;
    }

    @Override
    public List<User> getUsersOfGroup(String groupID) throws IdentityStoreException {
        return null;
    }

    @Override
    public User addUser(Map<String, String> claims, Object credential, List<String> groupList)
            throws IdentityStoreException {
        return null;
    }

    @Override
    public Group addGroup(String groupName) throws IdentityStoreException {
        return null;
    }

    @Override
    public void assignGroupsToUser(String userId, List<Group> groups) throws IdentityStoreException {

    }

    @Override
    public void assingUsersToGroup(String groupId, List<User> identities) throws IdentityStoreException {

    }

    @Override
    public void updateCredential(String userID, Object newCredential) throws IdentityStoreException {

    }

    @Override
    public void updateCredential(String userID, Object oldCredential, Object newCredential)
            throws IdentityStoreException {

    }

    @Override
    public void setUserAttributeValues(String userID, Map<String, String> attributes) throws IdentityStoreException {

    }

    @Override
    public void deleteUserAttributeValues(String userID, List<String> attributes) throws IdentityStoreException {

    }

    @Override
    public void deleteUser(String userID) throws IdentityStoreException {

    }

    @Override
    public void deleteGroup(String groupId) throws IdentityStoreException {

    }

    @Override
    public boolean isReadOnly() throws IdentityStoreException {
        return false;
    }

    @Override
    public IdentityStoreConfig getIdentityStoreConfig() {
        return identityStoreConfig;
    }
}
