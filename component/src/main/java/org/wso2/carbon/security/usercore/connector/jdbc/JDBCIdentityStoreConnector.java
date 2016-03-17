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
import org.wso2.carbon.security.usercore.constant.ConnectorConstants;
import org.wso2.carbon.security.usercore.connector.IdentityStoreConnector;
import org.wso2.carbon.security.usercore.constant.DatabaseColumnNames;
import org.wso2.carbon.security.usercore.exception.IdentityStoreException;
import org.wso2.carbon.security.usercore.util.DatabaseUtil;
import org.wso2.carbon.security.usercore.util.NamedPreparedStatement;
import org.wso2.carbon.security.usercore.util.UnitOfWork;
import org.wso2.carbon.security.usercore.util.UserCoreUtil;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
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
    private String userStoreName;

    @Override
    public void init(IdentityStoreConfig identityStoreConfig) throws IdentityStoreException {

        Properties properties = identityStoreConfig.getStoreProperties();

        this.sqlStatements = (Map<String, String>) properties.get(ConnectorConstants.SQL_QUERIES);
        this.userStoreId = properties.getProperty(ConnectorConstants.USERSTORE_ID);
        this.userStoreName = properties.getProperty(ConnectorConstants.USERSTORE_NAME);
        this.identityStoreConfig = identityStoreConfig;
        try {
            dataSource = DatabaseUtil.getInstance()
                    .getDataSource(properties.getProperty(ConnectorConstants.DATA_SOURCE));
        } catch (DataSourceException e) {
            throw new IdentityStoreException("Error occured while initiating data source", e);
        }
    }

    @Override
    public String getUserStoreName() {
        return userStoreName;
    }

    @Override
    public String getUserStoreID() {
        return userStoreId;
    }

    @Override
    public User getUser(String username) throws IdentityStoreException {

        try (Connection connection = dataSource.getConnection()) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(connection,
                    sqlStatements.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_USER_FROM_USERNAME));
            namedPreparedStatement.setString("username", username);
            ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery();

            if (!resultSet.next()) {
                throw new IdentityStoreException("No user for given id");
            }

            String userId = resultSet.getString(DatabaseColumnNames.User.USER_UNIQUE_ID);
            return new User(userId, userStoreId, username);
        } catch (SQLException e) {
            throw new IdentityStoreException("Error occurred while retrieving user from database", e);
        }
    }

    @Override
    public User getUserFromId(String userID) throws IdentityStoreException {

        try (Connection connection = dataSource.getConnection()) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(connection,
                    sqlStatements.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_USER_FROM_ID));
            namedPreparedStatement.setString("userId", userID);
            ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery();

            if (!resultSet.next()) {
                throw new IdentityStoreException("No user for given id");
            }

            String username = resultSet.getString(DatabaseColumnNames.User.USERNAME);
            return new User(userID, userStoreId, username);
        } catch (SQLException e) {
            throw new IdentityStoreException("Error occurred while retrieving user from database", e);
        }
    }

    @Override
    public List<User> listUsers(String filterPattern, int offset, int length) throws IdentityStoreException {
        return null;
    }

    @Override
    public Map<String, String> getUserClaimValues(String userId) throws IdentityStoreException {

        try (Connection connection = dataSource.getConnection()) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(connection,
                    sqlStatements.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_USER_ATTRIBUTES));
            namedPreparedStatement.setString("userId", userId);
            ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery();

            Map<String, String> userClaims = new HashMap<>();
            while (resultSet.next()) {
                String attrName = resultSet.getString(DatabaseColumnNames.UserAttributes.ATTR_NAME);
                String attrValue = resultSet.getString(DatabaseColumnNames.UserAttributes.ATTR_VALUE);
                userClaims.put(attrName, attrValue);
            }
            return userClaims;
        } catch (SQLException e) {
            throw new IdentityStoreException("Error occurred while retrieving user claims from database", e);
        }

    }

    @Override
    public Map<String, String> getUserClaimValues(String userID, Set<String> claimURIs) throws IdentityStoreException {
        return null;
    }

    @Override
    public Group getGroup(String groupName) throws IdentityStoreException {

        try (Connection connection = dataSource.getConnection()) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(connection,
                    sqlStatements.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_GROUP_FROM_NAME));
            namedPreparedStatement.setString(DatabaseColumnNames.Group.GROUP_NAME, groupName);
            ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery();

            if (!resultSet.next()) {
                throw new IdentityStoreException("No group for given name");
            }

            String groupId = resultSet.getString(DatabaseColumnNames.Group.GROUP_UNIQUE_ID);
            return new Group(groupId, userStoreId, groupName);
        } catch (SQLException e) {
            throw new IdentityStoreException("Internal error occurred while communicating with database", e);
        }
    }

    @Override
    public Group getGroupById(String groupId) throws IdentityStoreException {

        try (Connection connection = dataSource.getConnection()) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(connection,
                    sqlStatements.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_GROUP_FROM_ID));
            namedPreparedStatement.setString(DatabaseColumnNames.Group.GROUP_UNIQUE_ID, groupId);
            ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery();

            if (!resultSet.next()) {
                throw new IdentityStoreException("No group for given id");
            }

            String groupName = resultSet.getString(DatabaseColumnNames.Group.GROUP_NAME);
            return new Group(groupId, userStoreId, groupName);
        } catch (SQLException e) {
            throw new IdentityStoreException("Internal error occurred while communicating with database", e);
        }
    }

    @Override
    public List<Group> listGroups(String attribute, String filter, int maxItemLimit) throws IdentityStoreException {
        return null;
    }

    @Override
    public List<Group> getGroupsOfUser(String userId) throws IdentityStoreException {

        try (Connection connection = dataSource.getConnection()) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(connection,
                    sqlStatements.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_GROUPS_OF_USER));
            namedPreparedStatement.setString(DatabaseColumnNames.Group.GROUP_UNIQUE_ID, userId);
            ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery();

            List<Group> groupList = new ArrayList<>();
            while (resultSet.next()) {
                String groupName = resultSet.getString(DatabaseColumnNames.Group.GROUP_NAME);
                String groupId = resultSet.getString(DatabaseColumnNames.Group.GROUP_UNIQUE_ID);
                Group group = new Group(groupId, userStoreId, groupName);
                groupList.add(group);
            }
            return groupList;
        } catch (SQLException e) {
            throw new IdentityStoreException("Internal error occurred while communicating with database", e);
        }
    }

    @Override
    public List<User> getUsersOfGroup(String groupId) throws IdentityStoreException {

        try (Connection connection = dataSource.getConnection()) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(connection,
                    sqlStatements.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_USERS_OF_GROUP));
            namedPreparedStatement.setString(DatabaseColumnNames.Group.GROUP_UNIQUE_ID, groupId);
            ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery();

            List<User> userList = new ArrayList<>();
            while (resultSet.next()) {
                String username = resultSet.getString(DatabaseColumnNames.User.USERNAME);
                String userId = resultSet.getString(DatabaseColumnNames.User.USER_UNIQUE_ID);
                User user = new User(userId, userStoreId, username);
                userList.add(user);
            }
            return userList;
        } catch (SQLException e) {
            throw new IdentityStoreException("Internal error occurred while communicating with database", e);
        }
    }

    @Override
    public User addUser(String username, Map<String, String> claims, Object credential, List<String> groupList)
            throws IdentityStoreException {

        long [] groupIds = new long[groupList.size()];

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            // TODO: Find a way to run multiple SELECT statements in a single transaction.

        } catch (SQLException e) {
            throw new IdentityStoreException("Error while retrieving group id's", e);
        }

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            String generatedUserId = UserCoreUtil.getRandomUserId();

            NamedPreparedStatement addUserPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlStatements.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_USER));
            addUserPreparedStatement.setString(DatabaseColumnNames.User.USERNAME, username);
            // TODO: Add the hashing algo.
            addUserPreparedStatement.setString(DatabaseColumnNames.User.PASSWORD,
                    UserCoreUtil.hashPassword((char[]) credential, "sha256"));
            addUserPreparedStatement.setString(DatabaseColumnNames.User.USER_UNIQUE_ID, generatedUserId);

            addUserPreparedStatement.getPreparedStatement().executeUpdate();
            ResultSet resultSet = addUserPreparedStatement.getPreparedStatement().getGeneratedKeys();

            if (!resultSet.next()) {
                throw new IdentityStoreException("Failed to add the user.");
            }

            long id = resultSet.getLong(1);

            NamedPreparedStatement addUserClaimsPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlStatements.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_USER_CLAIMS));

            for (Map.Entry<String, String> claim : claims.entrySet()) {
                addUserClaimsPreparedStatement.setLong(DatabaseColumnNames.UserAttributes.USER_ID, id);
                addUserClaimsPreparedStatement.setString(DatabaseColumnNames.UserAttributes.ATTR_NAME,
                        claim.getKey());
                addUserClaimsPreparedStatement.setString(DatabaseColumnNames.UserAttributes.ATTR_VALUE,
                        claim.getValue());
                addUserClaimsPreparedStatement.getPreparedStatement().addBatch();
            }
            addUserClaimsPreparedStatement.getPreparedStatement().executeBatch();
            return new User(generatedUserId, userStoreId, username);
        } catch (SQLException e) {
            throw new IdentityStoreException("Internal error occurred while adding the user", e);
        }
    }

    @Override
    public Group addGroup(String groupName) throws IdentityStoreException {
        return null;
    }

    @Override
    public void assignGroupsToUser(String userId, List<Group> groups) throws IdentityStoreException {

    }

    @Override
    public void assignUsersToGroup(String groupId, List<User> identities) throws IdentityStoreException {

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
    public void deleteUser(String userId) throws IdentityStoreException {

        try (Connection connection = dataSource.getConnection()) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(connection,
                    sqlStatements.get(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_USER));
            namedPreparedStatement.setString(DatabaseColumnNames.User.USER_UNIQUE_ID, userId);

            int rows = namedPreparedStatement.getPreparedStatement().executeUpdate();
            if (rows < 1) {
                throw new IdentityStoreException("User from given id does not exist.");
            }
        } catch (SQLException e) {
            throw new IdentityStoreException("Internal error occurred while communicating with database", e);
        }
    }

    @Override
    public void deleteGroup(String groupId) throws IdentityStoreException {

        try (Connection connection = dataSource.getConnection()) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(connection,
                    sqlStatements.get(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_GROUP));
            namedPreparedStatement.setString(DatabaseColumnNames.Group.GROUP_UNIQUE_ID, groupId);

            int rows = namedPreparedStatement.getPreparedStatement().executeUpdate();
            if (rows < 1) {
                throw new IdentityStoreException("Group from given id does not exist.");
            }
        } catch (SQLException e) {
            throw new IdentityStoreException("Internal error occurred while communicating with database", e);
        }
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
