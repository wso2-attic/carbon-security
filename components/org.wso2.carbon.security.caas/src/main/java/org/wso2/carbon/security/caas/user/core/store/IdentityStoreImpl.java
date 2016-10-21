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
import org.wso2.carbon.security.caas.api.util.CarbonSecurityConstants;
import org.wso2.carbon.security.caas.internal.CarbonSecurityDataHolder;
import org.wso2.carbon.security.caas.user.core.bean.Domain;
import org.wso2.carbon.security.caas.user.core.bean.Group;
import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.claim.Claim;
import org.wso2.carbon.security.caas.user.core.claim.MetaClaim;
import org.wso2.carbon.security.caas.user.core.claim.MetaClaimMapping;
import org.wso2.carbon.security.caas.user.core.domain.DomainManager;
import org.wso2.carbon.security.caas.user.core.exception.DomainException;
import org.wso2.carbon.security.caas.user.core.exception.GroupNotFoundException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.exception.UserNotFoundException;
import org.wso2.carbon.security.caas.user.core.service.RealmService;
import org.wso2.carbon.security.caas.user.core.store.connector.IdentityStoreConnector;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Represents a virtual identity store to abstract the underlying stores.
 *
 * @since 1.0.0
 */
public class IdentityStoreImpl implements IdentityStore {

    private static final Logger log = LoggerFactory.getLogger(IdentityStoreImpl.class);

    private DomainManager domainManager;

    private RealmService carbonRealmService;

    @Override
    public void init(DomainManager domainManager)
            throws IdentityStoreException {

        this.domainManager = domainManager;
        this.carbonRealmService = CarbonSecurityDataHolder.getInstance().getCarbonRealmService();

        if (log.isDebugEnabled()) {
            log.debug("Identity store successfully initialized.");
        }
    }


    @Override
    public Group getGroup(Claim claim, String domain) throws IdentityStoreException, GroupNotFoundException {
        return null;
    }

    @Override
    public List<Group> listGroups(int offset, int length) throws IdentityStoreException {
        return null;
    }

    @Override
    public List<Group> listGroups(int offset, int length, String domain) throws IdentityStoreException {
        return null;
    }

    @Override
    public List<Group> listGroups(Claim claim, int offset, int length) throws IdentityStoreException {
        return null;
    }

    @Override
    public List<Group> listGroups(Claim claim, int offset, int length, String domain) throws IdentityStoreException {
        return null;
    }

    @Override
    public List<Group> listGroups(MetaClaim metaClaim, String filterPattern, int offset, int length)
            throws IdentityStoreException {
        return null;
    }

    @Override
    public List<Group> listGroups(MetaClaim metaClaim, String filterPattern, int offset, int length, String domain)
            throws IdentityStoreException {
        return null;
    }

    @Override
    public User getUser(String username)
            throws IdentityStoreException, UserNotFoundException {

        Claim claim = new Claim();
        claim.setDialectURI("http://wso2.org/claims"); // TODO: Set the dialect URI for the primary attribute.
        claim.setClaimURI("http://wso2.org/claims/username"); // TODO: Set the URI for the primary attribute.
        claim.setValue(username);

        return getUser(claim);
    }

    @Override
    public User getUser(String userId, String domain) throws IdentityStoreException, UserNotFoundException {
        return null;
    }

    @Override
    public User getUser(Claim claim) throws IdentityStoreException, UserNotFoundException {

        String attributeValue = claim.getValue();

        Domain domain = resolveUserDomain(attributeValue);

        String claimURI = claim.getClaimURI();

        Map<String, List<MetaClaimMapping>> metaClaimMappings = domain.getClaimMappings();

        MetaClaimMapping metaClaimMapping = null;

        for (Map.Entry<String, List<MetaClaimMapping>> entry : metaClaimMappings.entrySet()) {

            for (MetaClaimMapping metaClaimMappingEntry : entry.getValue()) {
                if (metaClaimMappingEntry.getMetaClaim().getClaimURI().equals(claimURI)) {
                    metaClaimMapping = metaClaimMappingEntry;
                }
            }
        }

        if (metaClaimMapping == null) {
            throw new IdentityStoreException("Claim URI " + claimURI + " was not found");
        }

        String attributeName = metaClaimMapping.getAttributeName();

        String[] domainSplit = attributeValue.split(CarbonSecurityConstants.URL_SPLITTER);

        String domainUnawareAttributeValue;

        if (domainSplit.length > 1) {
            domainUnawareAttributeValue = domainSplit[1];
        } else {
            domainUnawareAttributeValue = attributeValue;
        }

        IdentityStoreConnector identityStoreConnector =
                domain.getIdentityStoreConnectorFromId(metaClaimMapping.getIdentityStoreConnectorId());

        User.UserBuilder userBuilder =
                identityStoreConnector.getUserBuilder(attributeName, domainUnawareAttributeValue);

        userBuilder.setDomain(domain)
                .setUserId(domainUnawareAttributeValue)
                .setIdentityStore(carbonRealmService.getIdentityStore())
                .setAuthorizationStore(carbonRealmService.getAuthorizationStore())
                .setClaimManager(carbonRealmService.getClaimManager());

        return userBuilder.build();
    }

    @Override
    public User getUser(Claim claim, String domain) throws IdentityStoreException, UserNotFoundException {
        return null;
    }

    @Override
    public List<User> listUsers(int offset, int length) throws IdentityStoreException {
        return null;
    }

    @Override
    public List<User> listUsers(int offset, int length, String domain) throws IdentityStoreException {
        return null;
    }

    @Override
    public List<User> listUsers(Claim claim, int offset, int length) throws IdentityStoreException {

        List<User> users = new ArrayList<>();

        String attributeName = claim.getClaimURI(); // TODO: Get the attribute name from the claim manager.
        String attributeValue = claim.getValue();

        Map<String, IdentityStoreConnector> identityStoreConnectorsMap =
                resolveDomain(claim).getIdentityStoreConnectorMap();

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

                for (User.UserBuilder userBuilder
                        : identityStoreConnector.getUserBuilderList(attributeName, attributeValue, offset, length)) {

                    users.add(buildUser(userBuilder));
                }

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
    public List<User> listUsers(Claim claim, int offset, int length, String domain) throws IdentityStoreException {
        return null;
    }

    @Override
    public List<User> listUsers(MetaClaim metaClaim, String filterPattern, int offset, int length)
            throws IdentityStoreException {
        return null;
    }

    @Override
    public List<User> listUsers(MetaClaim metaClaim, String filterPattern, int offset, int length, String domain)
            throws IdentityStoreException {
        return null;
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
    public Group getGroup(String groupId, String domain) throws IdentityStoreException, GroupNotFoundException {
        return null;
    }

    @Override
    public Group getGroup(Claim claim) throws IdentityStoreException, GroupNotFoundException {

        String attributeName = claim.getClaimURI(); // TODO: Get the attribute name from the claim uri.
        String attributeValue = claim.getValue();

        Map<String, IdentityStoreConnector> identityStoreConnectorsMap =
                resolveDomain(claim).getIdentityStoreConnectorMap();

        for (IdentityStoreConnector identityStoreConnector : identityStoreConnectorsMap.values()) {

            // TODO: Set domain for group builder
            // TODO: Consider the logic in this loop

            return identityStoreConnector.getGroupBuilder(attributeName, attributeValue)
                    .setIdentityStore(carbonRealmService.getIdentityStore())
                    .setAuthorizationStore(carbonRealmService.getAuthorizationStore())
                    .build();
        }
        throw new GroupNotFoundException("Group not found for the given name");
    }

    @Override
    public List<Group> getGroupsOfUser(String username) throws IdentityStoreException {

        List<Group> groupList = new ArrayList<>();

        Map<String, IdentityStoreConnector> identityStoreConnectorsMap;

        try {
            identityStoreConnectorsMap = domainManager
                    .getDomainFromUserName(username).getIdentityStoreConnectorMap();
        } catch (DomainException e) {
            throw new IdentityStoreException(e);
        }

        // TODO: Set domain for group builder
        for (IdentityStoreConnector identityStoreConnector : identityStoreConnectorsMap.values()) {
            groupList.addAll(identityStoreConnector.getGroupBuildersOfUser(username)
                    .stream()
                    .map(groupBuilder -> groupBuilder
                            .setAuthorizationStore(carbonRealmService.getAuthorizationStore())
                            .setIdentityStore(carbonRealmService.getIdentityStore())
                            .build())
                    .collect(Collectors.toList()));
        }

        return groupList;
    }

    @Override
    public List<User> getUsersOfGroup(String groupID) throws IdentityStoreException {

        List<User> userList = new ArrayList<>();

        Map<String, IdentityStoreConnector> identityStoreConnectorsMap =
                resolveGroupDomain(groupID).getIdentityStoreConnectorMap();

        for (IdentityStoreConnector identityStoreConnector : identityStoreConnectorsMap.values()) {

            for (User.UserBuilder userBuilder
                    : identityStoreConnector.getUserBuildersOfGroup(groupID)) {

                userList.add(buildUser(userBuilder));
            }
        }

        return userList;
    }

    @Override
    public List<Group> getGroupsOfUser(String userId, String domain) throws IdentityStoreException {
        return null;
    }

    @Override
    public List<User> getUsersOfGroup(String groupId, String domain) throws IdentityStoreException {
        return null;
    }

    @Override
    public boolean isUserInGroup(String userName, String groupId) throws IdentityStoreException {

        Map<String, IdentityStoreConnector> identityStoreConnectorsMap;

        try {
            identityStoreConnectorsMap = this.domainManager
                    .getDomainFromUserName(userName).getIdentityStoreConnectorMap();
        } catch (DomainException e) {
            throw new IdentityStoreException(e);
        }

        for (IdentityStoreConnector identityStoreConnector : identityStoreConnectorsMap.values()) {

            if (identityStoreConnector.isUserInGroup(userName, groupId)) {
                return true;
            }
        }

        return false;
    }

    @Override
    public boolean isUserInGroup(String userId, String groupId, String domain) throws IdentityStoreException {
        return false;
    }

    /**
     * Build a user instance from a user builder.
     *
     * @param userBuilder User.UserBuilder
     * @return User user instance
     * @throws IdentityStoreException identity exception
     */
    private User buildUser(User.UserBuilder userBuilder) throws IdentityStoreException {

        try {
            return userBuilder.setDomain(domainManager.getDomainFromUserName(userBuilder.getUserId()))
                    .setIdentityStore(carbonRealmService.getIdentityStore())
                    .setAuthorizationStore(carbonRealmService.getAuthorizationStore())
                    .setClaimManager(carbonRealmService.getClaimManager())
                    .build();
        } catch (DomainException e) {
            throw new IdentityStoreException(String
                    .format("Error occurred in building user %s from user builder",
                            userBuilder.getUserId()), e);
        }
    }

    /**
     * Resolve the domain for a given attribute.
     *
     * @param claim Claim
     * @return The domain for the user.
     * @throws IdentityStoreException identity storeexception
     */
    private Domain resolveDomain(Claim claim) throws IdentityStoreException {

        try {
            return this.domainManager.getDomainFromClaim(claim);
        } catch (DomainException e) {
            throw new IdentityStoreException("Resolving domain from claim failed", e);
        }
    }

    // TODO: Resolve domain from String filter pattern and group ID
    private Domain resolveGroupDomain(String groupId) {
        return null;
    }

    private Domain resolveUserDomain(String attributeValue) throws IdentityStoreException {
        try {
            return domainManager.getDomainFromUserName(attributeValue);
        } catch (DomainException e) {
            throw new IdentityStoreException("Error resolving domain", e);
        }
    }
}

