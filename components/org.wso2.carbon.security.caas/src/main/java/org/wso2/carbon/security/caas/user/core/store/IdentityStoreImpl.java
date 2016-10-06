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

package org.wso2.carbon.security.caas.user.core.store;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.security.caas.internal.CarbonSecurityDataHolder;
import org.wso2.carbon.security.caas.user.core.bean.Attribute;
import org.wso2.carbon.security.caas.user.core.bean.Domain;
import org.wso2.carbon.security.caas.user.core.bean.Group;
import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.claim.Claim;
import org.wso2.carbon.security.caas.user.core.config.IdentityStoreConnectorConfig;
import org.wso2.carbon.security.caas.user.core.constant.UserCoreConstants;
import org.wso2.carbon.security.caas.user.core.exception.GroupNotFoundException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.exception.StoreException;
import org.wso2.carbon.security.caas.user.core.exception.UserNotFoundException;
import org.wso2.carbon.security.caas.user.core.store.connector.IdentityStoreConnector;
import org.wso2.carbon.security.caas.user.core.store.connector.IdentityStoreConnectorFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.security.auth.callback.Callback;

/**
 * Represents a virtual identity store to abstract the underlying stores.
 *
 * @since 1.0.0
 */
public class IdentityStoreImpl implements IdentityStore {

    private static final Logger log = LoggerFactory.getLogger(IdentityStoreImpl.class);

    // Domain is required because the User.UserBuilder requires a domain instance
    private Domain domain;
    private Map<String, IdentityStoreConnector> identityStoreConnectorsMap = new HashMap<>();

    @Override
    public void init(Domain domain, Map<String, IdentityStoreConnectorConfig> identityConnectorConfigs)
            throws IdentityStoreException {

        this.domain = domain;

        if (identityConnectorConfigs.isEmpty()) {
            throw new StoreException("At least one identity store configuration must present.");
        }

        for (Map.Entry<String, IdentityStoreConnectorConfig> identityStoreConfig :
                identityConnectorConfigs.entrySet()) {

            String connectorType = identityStoreConfig.getValue().getConnectorType();
            IdentityStoreConnectorFactory identityStoreConnectorFactory = CarbonSecurityDataHolder.getInstance()
                    .getIdentityStoreConnectorFactoryMap().get(connectorType);

            if (identityStoreConnectorFactory == null) {
                throw new StoreException("No identity store connector factory found for given type.");
            }

            IdentityStoreConnector identityStoreConnector = identityStoreConnectorFactory.getConnector();
            identityStoreConnector.init(identityStoreConfig.getKey(), identityStoreConfig.getValue());

            identityStoreConnectorsMap.put(identityStoreConfig.getKey(), identityStoreConnector);
        }

        if (log.isDebugEnabled()) {
            log.debug("Identity store successfully initialized.");
        }
    }

    @Override
    public User getUser(String username) throws IdentityStoreException, UserNotFoundException {

        Claim claim = new Claim();
        claim.setDialectURI(""); // TODO: Set the dialect URI for the primary attribute.
        claim.setClaimURI(""); // TODO: Set the URI for the primary attribute.
        claim.setValue(username);

        return getUser(claim);
    }

    @Override
    public User getUser(Claim claim) throws IdentityStoreException, UserNotFoundException {

        UserNotFoundException userNotFoundException = new UserNotFoundException("User not found for the given name.");

        String attributeName = claim.getClaimURI(); // TODO: Get the attribute name from the claim manager.
        String attributeValue = claim.getValue();

        for (IdentityStoreConnector identityStoreConnector : identityStoreConnectorsMap.values()) {
            try {
                User.UserBuilder userBuilder = identityStoreConnector.getUserBuilder(attributeName, attributeValue);
                return userBuilder.setDomain(domain)
                        .setIdentityStore(domain.getIdentityStore())
                        .setAuthorizationStore(CarbonSecurityDataHolder
                                .getInstance().getCarbonRealmService().getAuthorizationStore())
                        .setClaimManager(CarbonSecurityDataHolder
                                .getInstance().getCarbonRealmService().getClaimManager())
                        .build();
            } catch (UserNotFoundException e) {
                userNotFoundException.addSuppressed(e);
            }
        }
        throw userNotFoundException;
    }

    // TODO: <VIDURA> Is it correct to throw an exception here?
    @Override
    public User getUser(Callback[] callbacks) throws IdentityStoreException, UserNotFoundException {

        UserNotFoundException userNotFoundException = new
                UserNotFoundException("User not found for the given callbacks.");

        for (IdentityStoreConnector identityStoreConnector : identityStoreConnectorsMap.values()) {
            try {
                return identityStoreConnector.getUserBuilder(callbacks)
                        .setIdentityStore(domain.getIdentityStore())
                        .setAuthorizationStore(CarbonSecurityDataHolder
                                .getInstance().getCarbonRealmService().getAuthorizationStore())
                        .setClaimManager(CarbonSecurityDataHolder
                                .getInstance().getCarbonRealmService().getClaimManager())
                        .build();
            } catch (UserNotFoundException e) {
                userNotFoundException.addSuppressed(e);
            }
        }
        throw userNotFoundException;
    }

    @Override
    public List<User> listUsers(String filterPattern, int offset, int length) throws IdentityStoreException {

        Claim claim = new Claim();
        claim.setDialectURI(""); // TODO: Set the dialect URI for the primary attribute.
        claim.setClaimURI(""); // TODO: Set the URI for the primary attribute.
        claim.setValue(filterPattern);

        return listUsers(claim, offset, length);
    }

    @Override
    public List<User> listUsers(Claim claim, int offset, int length) throws IdentityStoreException {

        List<User> users = new ArrayList<>();

        String attributeName = claim.getClaimURI(); // TODO: Get the attribute name from the claim manager.
        String attributeValue = claim.getValue();

        int userCount = 0;
        
        for (IdentityStoreConnector identityStoreConnector : identityStoreConnectorsMap.values()) {

            // Get the total count of users in the identity store.
            try {
                userCount += identityStoreConnector.getUserCount();
            } catch (UnsupportedOperationException e) {
                log.warn("Count operation is not supported by this identity store. Running the operation in " +
                        "performance intensive mode.");
                userCount += identityStoreConnector.getUserBuilderList(attributeName, "*", 0, -1).size();
            }

            // If there are users in this identity store more than the offset, we can get users from this offset.
            // If this offset exceeds the available count of the current identity store, move to the next
            // identity store.
            if (userCount > offset) {
                users.addAll(identityStoreConnector.getUserBuilderList(attributeName, attributeValue, offset, length)
                        .stream()
                        .map(userBuilder -> userBuilder
                                .setIdentityStore(domain.getIdentityStore())
                                .setAuthorizationStore(CarbonSecurityDataHolder
                                        .getInstance().getCarbonRealmService().getAuthorizationStore())
                                .setClaimManager(CarbonSecurityDataHolder
                                        .getInstance().getCarbonRealmService().getClaimManager())
                                .build())
                        .collect(Collectors.toList()));
                length -= users.size();
                offset = 0;
            } else {
                offset -= userCount;
            }

            // If we retrieved all the required users.
            if (length == 0) {
                break;
            }
        }

        return users;
    }

    @Override
    public List<Attribute> getUserAttributeValues(String userID, Domain domain) throws IdentityStoreException {

        List<Attribute> userAttributes = new ArrayList<>();

        for (IdentityStoreConnector identityStoreConnector : identityStoreConnectorsMap.values()) {
            userAttributes.addAll(identityStoreConnector.getUserAttributeValues(userID));
        }

        return userAttributes;
    }

    @Override
    public List<Attribute> getUserAttributeValues(String userID, List<String> attributeNames, Domain domain)
            throws IdentityStoreException {

        List<Attribute> userAttributes = new ArrayList<>();

        for (IdentityStoreConnector identityStoreConnector : identityStoreConnectorsMap.values()) {
            userAttributes.addAll(identityStoreConnector.getUserAttributeValues(userID, attributeNames));
        }

        return userAttributes;
    }

    @Override
    public Group getGroup(String groupName) throws IdentityStoreException, GroupNotFoundException {

        Claim claim = new Claim();
        claim.setDialectURI(""); // TODO: Set the dialect URI for the primary attribute.
        claim.setClaimURI(""); // TODO: Set the URI for the primary attribute.
        claim.setValue(groupName);

        return getGroup(claim);
    }

    @Override
    public Group getGroup(Claim claim) throws IdentityStoreException, GroupNotFoundException {

        String attributeName = claim.getClaimURI(); // TODO: Get the attribute name from the claim uri.
        String attributeValue = claim.getValue();

        GroupNotFoundException groupNotFoundException =
                new GroupNotFoundException("Group not found for the given name");

        for (IdentityStoreConnector identityStoreConnector : identityStoreConnectorsMap.values()) {
            try {
                return identityStoreConnector.getGroupBuilder(attributeName, attributeValue)
                        .setIdentityStore(domain.getIdentityStore())
                        .setAuthorizationStore(CarbonSecurityDataHolder
                                .getInstance().getCarbonRealmService().getAuthorizationStore())
                        .build();
            } catch (GroupNotFoundException e) {
                groupNotFoundException.addSuppressed(e);
            }
        }
        throw groupNotFoundException;
    }

    // TODO: Create method to list group by Claim.

    @Override
    public List<Group> listGroups(String filterPattern, int offset, int length) throws IdentityStoreException {

        List<Group> groups = new ArrayList<>();

        int groupCount = 0;
        
        for (IdentityStoreConnector identityStoreConnector : identityStoreConnectorsMap.values()) {

            // Get the total count of groups in the identity store
            try {
                groupCount += identityStoreConnector.getGroupCount();
            } catch (UnsupportedOperationException e) {
                log.warn("Count operation is not supported by this identity store. Running the operation in " +
                        "performance intensive mode.");
                groupCount += identityStoreConnector.getGroupBuilderList("*", 0, -1).size();
            }

            // If there are groups in this identity store more than the offset, we can get groups from this offset.
            // If this offset exceeds the available count of the current identity store, move to the next
            // identity store.
            if (groupCount > offset) {
                groups.addAll(identityStoreConnector.getGroupBuilderList(filterPattern, offset, length)
                        .stream()
                        .map(groupBuilder -> groupBuilder
                                .setIdentityStore(domain.getIdentityStore())
                                .setAuthorizationStore(CarbonSecurityDataHolder
                                        .getInstance().getCarbonRealmService().getAuthorizationStore())
                                .build())
                        .collect(Collectors.toList()));
                length -= groups.size();
                offset = 0;
            } else {
                offset -= groupCount;
            }

            // If we retrieved all the required users.
            if (length == 0) {
                break;
            }
        }

        return groups;
    }

    @Override
    public List<Attribute> getGroupAttributeValues(String groupId, Domain domain)
            throws IdentityStoreException {

        List<Attribute> groupAttributes = new ArrayList<>();

        for (IdentityStoreConnector identityStoreConnector : identityStoreConnectorsMap.values()) {
            groupAttributes.addAll(identityStoreConnector.getGroupAttributeValues(groupId));
        }

        return groupAttributes;
    }

    @Override
    public List<Attribute> getGroupAttributeValues(String groupId, Domain domain, List<String> attributeNames)
            throws IdentityStoreException {

        List<Attribute> groupAttributes = new ArrayList<>();

        for (IdentityStoreConnector identityStoreConnector : identityStoreConnectorsMap.values()) {
            groupAttributes.addAll(identityStoreConnector.getGroupAttributeValues(groupId, attributeNames));
        }

        return groupAttributes;
    }

    @Override
    public List<Group> getGroupsOfUser(String userId, Domain userDomain) throws IdentityStoreException {

        List<Group> groupList = new ArrayList<>();

        for (IdentityStoreConnector identityStoreConnector : identityStoreConnectorsMap.values()) {
            groupList.addAll(identityStoreConnector.getGroupBuildersOfUser(userId)
                    .stream()
                    .map(groupBuilder -> groupBuilder
                            .setAuthorizationStore(CarbonSecurityDataHolder
                                    .getInstance().getCarbonRealmService().getAuthorizationStore())
                            .setIdentityStore(domain.getIdentityStore())
                            .build())
                    .collect(Collectors.toList()));
        }

        return groupList;
    }

    @Override
    public List<User> getUsersOfGroup(String groupID, Domain groupDomain) throws IdentityStoreException {

        List<User> userList = new ArrayList<>();

        for (IdentityStoreConnector identityStoreConnector : identityStoreConnectorsMap.values()) {
            userList.addAll(identityStoreConnector.getUserBuildersOfGroup(groupID)
                    .stream()
                    .map(userBuilder -> userBuilder
                            .setIdentityStore(domain.getIdentityStore())
                            .setAuthorizationStore(CarbonSecurityDataHolder
                                    .getInstance().getCarbonRealmService().getAuthorizationStore())
                            .setClaimManager(CarbonSecurityDataHolder
                                    .getInstance().getCarbonRealmService().getClaimManager())
                            .build())
                    .collect(Collectors.toList()));
        }

        return userList;
    }

    @Override
    public boolean isUserInGroup(String userId, String groupId) throws IdentityStoreException {

        for (IdentityStoreConnector identityStoreConnector : identityStoreConnectorsMap.values()) {

            if (identityStoreConnector.isUserInGroup(userId, groupId)) {
                return true;
            }
        }

        return false;
    }

    @Override
    public Map<String, String> getAllIdentityStoreNames() {
        return identityStoreConnectorsMap.entrySet()
                .stream()
                .collect(Collectors.toMap(Map.Entry::getKey,
                        entry -> entry.getValue().getIdentityStoreConfig().getStoreProperties()
                                .getProperty(UserCoreConstants.USERSTORE_DISPLAY_NAME, "")));
    }
}
