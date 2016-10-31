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

package org.wso2.carbon.security.caas.userstore.filebased.connector;

import org.wso2.carbon.security.caas.user.core.bean.Attribute;
import org.wso2.carbon.security.caas.user.core.bean.Group;
import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.config.IdentityStoreConnectorConfig;
import org.wso2.carbon.security.caas.user.core.exception.GroupNotFoundException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.exception.UserNotFoundException;
import org.wso2.carbon.security.caas.user.core.store.connector.IdentityStoreConnector;
import org.wso2.carbon.security.caas.userstore.filebased.Constants;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * FileBased IdentityStoreConnector implementation for test usage.
 */
public class FileBasedIdentityStoreConnector implements IdentityStoreConnector {

    String identityStoreConnectorId;
    IdentityStoreConnectorConfig identityStoreConnectorConfig;

    private static final int PRIMARY_ATTRIBUTE_COLUMN = 1;

    /**
     * Attribute order of the csv file. Attribute Name vs position.
     */
    Map<String, Integer> attributeMap;

    /**
     * Number of columns represented in the csv.
     */
    private int numberOfColumns = 7;

    private Path userStorePath;

    @Override
    public void init(IdentityStoreConnectorConfig identityStoreConnectorConfig)
            throws IdentityStoreException {

        this.identityStoreConnectorConfig = identityStoreConnectorConfig;
        identityStoreConnectorId = identityStoreConnectorConfig.getConnectorId();

        String userStoreFile = identityStoreConnectorConfig.getProperties().getProperty("storeFile");

        if (userStoreFile == null) {
            throw new IdentityStoreException("storeFile property is not provided for connector " +
                    identityStoreConnectorId);
        }

        userStorePath = Paths.get(userStoreFile);

        populateAttributeMap();
    }

    /**
     * Populate attribute order of the csv file.
     */
    private void populateAttributeMap() {
        attributeMap = new HashMap<>();

        attributeMap.put("username", 1);
        attributeMap.put("email", 2);
        attributeMap.put("firstName", 3);
        attributeMap.put("lastName", 4);
        attributeMap.put("address", 5);
        attributeMap.put("phone", 6);
    }

    @Override
    public String getIdentityStoreConnectorId() {
        return identityStoreConnectorId;
    }

    @Override
    public User.UserBuilder getUserBuilder(String attributeName, String attributeValue) throws UserNotFoundException,
            IdentityStoreException {

        try (BufferedReader bufferedReader = Files.newBufferedReader(userStorePath)) {

            String line;
            while ((line = bufferedReader.readLine()) != null) {

                // Skip comments
                if (line.startsWith(Constants.COMMENT_PREFIX)) {
                    continue;
                }

                // Can have empty attributes, therefore having -1 for split
                String[] userData = line.split(Constants.DELIMITER, -1);

                if (userData.length != numberOfColumns) {
                    throw new IdentityStoreException("Invalid user data found in connector " +
                            identityStoreConnectorId);
                }

                Integer attributePosition = attributeMap.get(attributeName);

                if (attributePosition == null) {
                    throw new UserNotFoundException("Attribute " + attributeName + " is not found in the connector " +
                            identityStoreConnectorId);
                }

                // Check if this is the same user
                if (userData[attributePosition].equals(attributeValue)) {
                    return createUserBuilder(userData[PRIMARY_ATTRIBUTE_COLUMN]);
                }
            }

            throw new UserNotFoundException("User " + attributeName + " was not found");
        } catch (IOException e) {
            throw new IdentityStoreException("Error retrieving user mappings from connector " +
                    identityStoreConnectorId, e);
        }
    }

    @Override
    public int getUserCount() throws IdentityStoreException {

        int userCount = 0;

        try (BufferedReader bufferedReader = Files.newBufferedReader(userStorePath)) {
            String line;
            while ((line = bufferedReader.readLine()) != null) {

                // Skip comments
                if (line.startsWith(Constants.COMMENT_PREFIX)) {
                    continue;
                }

                userCount++;
            }

            return userCount;
        } catch (IOException e) {
            throw new IdentityStoreException("Error getting user count from connector " + identityStoreConnectorId, e);
        }
    }

    @Override
    public List<User.UserBuilder> getUserBuilderList(String attributeName, String filterPattern, int offset, int
            length) throws IdentityStoreException {
        Pattern pattern = Pattern.compile("(" + filterPattern + ")");

        try (BufferedReader bufferedReader = Files.newBufferedReader(userStorePath)) {

            List<User.UserBuilder> userBuilderList = new ArrayList<>();

            int position = 0;

            String line;
            while ((line = bufferedReader.readLine()) != null) {

                // Skip to the offset
                if (position < offset) {
                    continue;
                }

                // Skip comments
                if (line.startsWith(Constants.COMMENT_PREFIX)) {
                    continue;
                }

                // Can have empty attributes, therefore having -1 for split
                String[] userData = line.split(Constants.DELIMITER, -1);

                if (userData.length != numberOfColumns) {
                    throw new IdentityStoreException("Invalid user data found in connector " +
                            identityStoreConnectorId);
                }

                Integer attributePosition = attributeMap.get(attributeName);

                if (attributePosition == null) {
                    throw new IdentityStoreException("Attribute " + attributeName + " is not found in the connector "
                            + identityStoreConnectorId);
                }

                // Check if this is the same user
                Matcher matcher = pattern.matcher(userData[attributePosition]);

                if (matcher.find()) {
                    userBuilderList.add(createUserBuilder(userData[PRIMARY_ATTRIBUTE_COLUMN]));

                    if (userBuilderList.size() == length) {
                        break;
                    }
                }
            }

            return userBuilderList;
        } catch (IOException e) {
            throw new IdentityStoreException("Error retrieving user mappings from connector " +
                    identityStoreConnectorId, e);
        }
    }

    @Override
    public List<User.UserBuilder> getAllUserBuilderList(String attributeName, String filterPattern)
            throws IdentityStoreException {
        Pattern pattern = Pattern.compile("(" + filterPattern + ")");

        try (BufferedReader bufferedReader = Files.newBufferedReader(userStorePath)) {

            List<User.UserBuilder> userBuilderList = new ArrayList<>();

            String line;
            while ((line = bufferedReader.readLine()) != null) {

                // Skip comments
                if (line.startsWith(Constants.COMMENT_PREFIX)) {
                    continue;
                }

                // Can have empty attributes, therefore having -1 for split
                String[] userData = line.split(Constants.DELIMITER, -1);

                if (userData.length != numberOfColumns) {
                    throw new IdentityStoreException("Invalid user data found in connector " +
                            identityStoreConnectorId);
                }

                Integer attributePosition = attributeMap.get(attributeName);

                if (attributePosition == null) {
                    throw new IdentityStoreException("Attribute " + attributeName + " is not found in the connector " +
                            identityStoreConnectorId);
                }

                // Check if this is the same user
                Matcher matcher = pattern.matcher(userData[attributePosition]);

                if (matcher.find()) {
                    userBuilderList.add(createUserBuilder(userData[PRIMARY_ATTRIBUTE_COLUMN]));
                }
            }

            return userBuilderList;
        } catch (IOException e) {
            throw new IdentityStoreException("Error retrieving user mappings from connector" +
                    identityStoreConnectorId, e);
        }
    }

    @Override
    public List<Attribute> getUserAttributeValues(String userID) throws IdentityStoreException {
        try (BufferedReader bufferedReader = Files.newBufferedReader(userStorePath)) {

            String line;
            while ((line = bufferedReader.readLine()) != null) {

                // Skip comments
                if (line.startsWith(Constants.COMMENT_PREFIX)) {
                    continue;
                }

                // Can have empty attributes, therefore having -1 for split
                String[] userData = line.split(Constants.DELIMITER, -1);

                if (userData.length != numberOfColumns) {
                    throw new IdentityStoreException("Invalid user data found in connector " +
                            identityStoreConnectorId);
                }

                // Check if this is the same user
                if (userData[PRIMARY_ATTRIBUTE_COLUMN].equals(userID)) {

                    return attributeMap.entrySet().stream().map(attributeMapEntry -> {
                        Attribute attribute = new Attribute();
                        attribute.setAttributeValue(attributeMapEntry.getKey());

                        String attributeValue = userData[attributeMapEntry.getValue()];
                        attribute.setAttributeValue(attributeValue);
                        return attribute;
                    }).collect(Collectors.toList());
                }
            }

            throw new IdentityStoreException("User with primary attribute " + userID + " was not found in connector" +
                    identityStoreConnectorId);
        } catch (IOException e) {
            throw new IdentityStoreException("Error retrieving user mappings from connector " +
                    identityStoreConnectorId, e);
        }
    }

    @Override
    public List<Attribute> getUserAttributeValues(String userID, List<String> attributeNames)
            throws IdentityStoreException {
        try (BufferedReader bufferedReader = Files.newBufferedReader(userStorePath)) {

            String line;
            while ((line = bufferedReader.readLine()) != null) {

                // Skip comments
                if (line.startsWith(Constants.COMMENT_PREFIX)) {
                    continue;
                }

                // Can have empty attributes, therefore having -1 for split
                String[] userData = line.split(Constants.DELIMITER, -1);

                if (userData.length != numberOfColumns) {
                    throw new IdentityStoreException("Invalid user data found in connector " +
                            identityStoreConnectorId);
                }

                // Check if this is the same user
                if (userData[PRIMARY_ATTRIBUTE_COLUMN].equals(userID)) {

                    return attributeMap.entrySet().stream()
                            .filter(attributeMapEntry -> attributeNames.contains(attributeMapEntry.getKey()))
                            .map(attributeMapEntry -> {
                        Attribute attribute = new Attribute();
                        attribute.setAttributeValue(attributeMapEntry.getKey());

                        String attributeValue = userData[attributeMapEntry.getValue()];
                        attribute.setAttributeValue(attributeValue);
                        return attribute;
                    }).collect(Collectors.toList());
                }
            }

            throw new IdentityStoreException("User with primary attribute " + userID + " was not found in connector " +
                    identityStoreConnectorId);
        } catch (IOException e) {
            throw new IdentityStoreException("Error retrieving user mappings from connector " +
                    identityStoreConnectorId, e);
        }
    }

    @Override
    public Group.GroupBuilder getGroupBuilder(String attributeName, String attributeValue)
            throws GroupNotFoundException, IdentityStoreException {
        return null;
    }

    @Override
    public int getGroupCount() throws IdentityStoreException {
        return 0;
    }

    @Override
    public List<Group.GroupBuilder> getGroupBuilderList(String filterPattern, int offset, int length) throws
            IdentityStoreException {
        return null;
    }

    @Override
    public List<Attribute> getGroupAttributeValues(String groupId) throws IdentityStoreException {
        return null;
    }

    @Override
    public List<Attribute> getGroupAttributeValues(String groupId, List<String> attributeNames) throws
            IdentityStoreException {
        return null;
    }

    @Override
    public List<Group.GroupBuilder> getGroupBuildersOfUser(String userID) throws IdentityStoreException {
        return null;
    }

    @Override
    public List<User.UserBuilder> getUserBuildersOfGroup(String groupID) throws IdentityStoreException {
        return null;
    }

    @Override
    public boolean isUserInGroup(String userId, String groupId) throws IdentityStoreException {
        return false;
    }

    @Override
    public boolean isReadOnly() throws IdentityStoreException {
        return true;
    }

    @Override
    public IdentityStoreConnectorConfig getIdentityStoreConfig() {
        return identityStoreConnectorConfig;
    }

    /**
     * Create a UserBuilder object from user Id.
     *
     * @param userId The user Id of the user
     * @return A UserBuilder with the given user Id
     */
    private User.UserBuilder createUserBuilder(String userId) {
        return new User.UserBuilder().setUserId(userId);
    }
}
