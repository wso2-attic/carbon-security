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
import java.security.NoSuchAlgorithmException;
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

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
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

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlStatements.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_USER_FROM_ID));
            namedPreparedStatement.setString("user_id", userID);
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

        List<User> userList = new ArrayList<>();

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement listUsersNamedPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlStatements.get(ConnectorConstants.QueryTypes.SQL_QUERY_LIST_USERS));
            listUsersNamedPreparedStatement.setString("username", filterPattern);
            listUsersNamedPreparedStatement.setInt("length", length);
            listUsersNamedPreparedStatement.setInt("offset", offset);

            ResultSet resultSet = listUsersNamedPreparedStatement.getPreparedStatement().executeQuery();

            while (resultSet.next()) {
                String userUniqueId = resultSet.getString(DatabaseColumnNames.User.USER_UNIQUE_ID);
                String username = resultSet.getString(DatabaseColumnNames.User.USERNAME);
                userList.add(new User(userUniqueId, userStoreId, username));
            }
        } catch (SQLException e) {
            throw new IdentityStoreException("Internal error occurred while listing users", e);
        }

        return userList;
    }

    @Override
    public Map<String, String> getUserClaimValues(String userId) throws IdentityStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlStatements.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_USER_ATTRIBUTES));
            namedPreparedStatement.setString("user_id", userId);
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

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlStatements.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_GROUP_FROM_NAME));
            namedPreparedStatement.setString("groupname", groupName);
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

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlStatements.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_GROUP_FROM_ID));
            namedPreparedStatement.setString("group_id", groupId);
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

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlStatements.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_GROUPS_OF_USER));
            namedPreparedStatement.setString("user_id", userId);
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

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlStatements.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_USERS_OF_GROUP));
            namedPreparedStatement.setString("group_id", groupId);
            ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery();

            List<User> userList = new ArrayList<>();
            while (resultSet.next()) {
                String username = resultSet.getString(DatabaseColumnNames.User.USERNAME);
                String userId = resultSet.getString(DatabaseColumnNames.User.USER_UNIQUE_ID);
                User user = new User(userId, userStoreId, username);
                userList.add(user);
            }

            unitOfWork.endTransaction();
            return userList;

        } catch (SQLException e) {
            throw new IdentityStoreException("Internal error occurred while communicating with database", e);
        }
    }

    /*
     * This process is happening in two separate transactions. First transaction is optional and in the first
     * transaction, related group ids will be retrieved from database if there are any in the group list. Second
     * transaction is happening in 3 batches. First user details will be added to the user table and second user
     * attributes will be added to the attributes table if there are any and finally user-group table will be updated
     * if there are any groups present.
     */
    @Override
    public User addUser(String username, Map<String, String> claims, Object credential, List<String> groupList)
            throws IdentityStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {

            List<Long> groupIds = new ArrayList<>();

            // Get the related group id's from the group names if there are any groups.
            if (groupList != null && !groupList.isEmpty()) {
                NamedPreparedStatement getGroupsPreparedStatement = new NamedPreparedStatement(
                        unitOfWork.getConnection(),
                        sqlStatements.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_GROUP_IDS),
                        groupList.size());
                getGroupsPreparedStatement.setString("groupnames", groupList);
                ResultSet resultSet = getGroupsPreparedStatement.getPreparedStatement().executeQuery();

                while (resultSet.next()) {
                    groupIds.add(resultSet.getLong(DatabaseColumnNames.Group.ID));
                }
            }

            String generatedUserId = UserCoreUtil.getRandomId();
            String salt = UserCoreUtil.getRandomId();

            // This will be hard coded for current implementation. Need to decide the method to add this dynamically.
            String hashAlgo = "SHA-256";

            NamedPreparedStatement addUserPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlStatements.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_USER));
            addUserPreparedStatement.setString("username", username);
            addUserPreparedStatement.setString("password",
                    UserCoreUtil.hashPassword((char[]) credential, salt, hashAlgo));
            addUserPreparedStatement.setString("user_unique_id", generatedUserId);

            addUserPreparedStatement.getPreparedStatement().executeUpdate();
            ResultSet resultSet = addUserPreparedStatement.getPreparedStatement().getGeneratedKeys();

            if (!resultSet.next()) {
                throw new IdentityStoreException("Failed to add the user.");
            }

            // Id of the user in the database.
            long userId = resultSet.getLong(1);

            // Add the password information.
            NamedPreparedStatement addPasswordInformationPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlStatements.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_PASSWORD_INFO));
            addPasswordInformationPreparedStatement.setLong("user_id", userId);
            addPasswordInformationPreparedStatement.setString("hash_algo", hashAlgo);
            addPasswordInformationPreparedStatement.setString("password_salt", salt);
            addPasswordInformationPreparedStatement.getPreparedStatement().executeUpdate();

            // Add user claims if there are any.
            if (claims != null && !claims.isEmpty()) {

                NamedPreparedStatement addUserClaimsPreparedStatement = new NamedPreparedStatement(
                        unitOfWork.getConnection(),
                        sqlStatements.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_USER_CLAIMS));

                for (Map.Entry<String, String> claim : claims.entrySet()) {
                    addUserClaimsPreparedStatement.setLong("user_id", userId);
                    addUserClaimsPreparedStatement.setString("attr_name", claim.getKey());
                    addUserClaimsPreparedStatement.setString("attr_val", claim.getValue());
                    addUserClaimsPreparedStatement.getPreparedStatement().addBatch();
                }
                addUserClaimsPreparedStatement.getPreparedStatement().executeBatch();
            }

            // Add groups if there are any.
            if (!groupIds.isEmpty()) {

                NamedPreparedStatement addUserGroupsPreparedStatement = new NamedPreparedStatement(
                        unitOfWork.getConnection(),
                        sqlStatements.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_USER_GROUPS));

                for (long groupId : groupIds) {
                    addUserGroupsPreparedStatement.setLong("user_id", userId);
                    addUserGroupsPreparedStatement.setLong("group_id", groupId);
                    addUserGroupsPreparedStatement.getPreparedStatement().addBatch();
                }
                addUserGroupsPreparedStatement.getPreparedStatement().executeBatch();
            }

            unitOfWork.endTransaction();
            return new User(generatedUserId, userStoreId, username);

        } catch (SQLException e) {
            throw new IdentityStoreException("Internal error occurred while adding the user.", e);
        } catch (NoSuchAlgorithmException e) {
            throw new IdentityStoreException("Invalid hash algorithm for password hashing.", e);
        }
    }

    @Override
    public Group addGroup(String groupName, List<String> users) throws IdentityStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {

            List<Long> userIds = new ArrayList<>();

            // Get all user ids if there are any users to be added.
            if (users != null && !users.isEmpty()) {
                NamedPreparedStatement getUserIdsPreparedStatement = new NamedPreparedStatement(
                        unitOfWork.getConnection(),
                        sqlStatements.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_USER_IDS));
                getUserIdsPreparedStatement.setString("usernames", users);
                ResultSet resultSet = getUserIdsPreparedStatement.getPreparedStatement().executeQuery();

                while (resultSet.next()) {
                    userIds.add(resultSet.getLong(DatabaseColumnNames.User.ID));
                }
            }

            String generatedGroupId = UserCoreUtil.getRandomId();

            NamedPreparedStatement addGroupPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlStatements.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_GROUP));
            addGroupPreparedStatement.setString("group_name", groupName);
            addGroupPreparedStatement.setString("unique_id", generatedGroupId);
            addGroupPreparedStatement.getPreparedStatement().executeUpdate();
            ResultSet resultSet = addGroupPreparedStatement.getPreparedStatement().getGeneratedKeys();

            if (!resultSet.next()) {
                throw new IdentityStoreException("Failed to add group");
            }

            long groupId = resultSet.getLong(1);

            if (!userIds.isEmpty()) {

                NamedPreparedStatement addGroupUsersPreparedStatement = new NamedPreparedStatement(
                        unitOfWork.getConnection(), ConnectorConstants.QueryTypes.SQL_QUERY_ADD_USER_GROUPS);
                for (long userId : userIds) {
                    addGroupUsersPreparedStatement.setLong("user_id", userId);
                    addGroupUsersPreparedStatement.setLong("group_id", groupId);
                    addGroupUsersPreparedStatement.getPreparedStatement().addBatch();
                }
            }

            unitOfWork.endTransaction();
            return new Group(generatedGroupId, userStoreId, groupName);

        } catch (SQLException e) {
            throw new IdentityStoreException("Internal error occurred while adding group.", e);
        }
    }

    @Override
    public void assignGroupsToUser(String userId, List<String> groups) throws IdentityStoreException {

        if (groups == null || groups.isEmpty()) {
            throw new IdentityStoreException("Groups list cannot be null or empty.");
        }

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {

            NamedPreparedStatement getGroupUniqueIdPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlStatements.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_USER_ID_FROM_UNIQUE_ID));
            getGroupUniqueIdPreparedStatement.setString("user_id", userId);

            ResultSet resultSet = getGroupUniqueIdPreparedStatement.getPreparedStatement().executeQuery();

            if (!resultSet.next()) {
                throw new IdentityStoreException("No user found for given unique id");
            }

            // Get the user DB id.
            long id = resultSet.getLong(DatabaseColumnNames.Group.ID);

            List<Long> groupIds = new ArrayList<>();

            NamedPreparedStatement getGroupIdsPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlStatements.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_GROUP_IDS));
            getGroupIdsPreparedStatement.setString("groupnames", groups);
            resultSet = getGroupIdsPreparedStatement.getPreparedStatement().executeQuery();

            while (!resultSet.next()) {
                groupIds.add(resultSet.getLong(DatabaseColumnNames.Group.ID));
            }

            NamedPreparedStatement assignUsersPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlStatements.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_USER_GROUPS));

            for (long groupId : groupIds) {
                assignUsersPreparedStatement.setLong("user_id", id);
                assignUsersPreparedStatement.setLong("group_id", groupId);
                assignUsersPreparedStatement.getPreparedStatement().addBatch();
            }
            assignUsersPreparedStatement.getPreparedStatement().executeBatch();
            unitOfWork.endTransaction();
        } catch (SQLException e) {
            throw new IdentityStoreException("Error occurred while assigning groups to user.", e);
        }

    }

    @Override
    public void assignUsersToGroup(String groupId, List<String> users) throws IdentityStoreException {

        if (users == null || users.isEmpty()) {
            throw new IdentityStoreException("Users list cannot be null or empty.");
        }

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {

            NamedPreparedStatement getGroupUniqueIdPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlStatements.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_GROUP_ID_FROM_UNIQUE_ID));
            getGroupUniqueIdPreparedStatement.setString("group_id", groupId);

            ResultSet resultSet = getGroupUniqueIdPreparedStatement.getPreparedStatement().executeQuery();

            if (!resultSet.next()) {
                throw new IdentityStoreException("No group found for given unique id");
            }

            // Get the group DB id.
            long id = resultSet.getLong(DatabaseColumnNames.Group.ID);

            List<Long> userIds = new ArrayList<>();

            NamedPreparedStatement getUserIdsPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlStatements.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_USER_IDS));
            getUserIdsPreparedStatement.setString("usernames", users);
            resultSet = getUserIdsPreparedStatement.getPreparedStatement().executeQuery();

            while (!resultSet.next()) {
                userIds.add(resultSet.getLong(DatabaseColumnNames.User.ID));
            }

            NamedPreparedStatement assignUsersPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlStatements.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_USER_GROUPS));

            for (long userId : userIds) {
                assignUsersPreparedStatement.setLong("group_id", id);
                assignUsersPreparedStatement.setLong("user_id", userId);
                assignUsersPreparedStatement.getPreparedStatement().addBatch();
            }
            assignUsersPreparedStatement.getPreparedStatement().executeBatch();
            unitOfWork.endTransaction();
        } catch (SQLException e) {
            throw new IdentityStoreException("Error occurred while assigning users to group.", e);
        }
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

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlStatements.get(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_USER));
            namedPreparedStatement.setString("user_id", userId);

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

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlStatements.get(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_GROUP));
            namedPreparedStatement.setString("group_id", groupId);

            int rows = namedPreparedStatement.getPreparedStatement().executeUpdate();
            if (rows < 1) {
                throw new IdentityStoreException("Group for given id does not exist.");
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
