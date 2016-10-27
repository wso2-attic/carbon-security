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
import org.wso2.carbon.security.caas.user.core.bean.Attribute;
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
import org.wso2.carbon.security.caas.user.core.exception.UserManagerException;
import org.wso2.carbon.security.caas.user.core.exception.UserNotFoundException;
import org.wso2.carbon.security.caas.user.core.service.RealmService;
import org.wso2.carbon.security.caas.user.core.store.connector.IdentityStoreConnector;
import org.wso2.carbon.security.caas.user.core.user.UserManager;

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

    private UserManager userManager;

    @Override
    public void init(DomainManager domainManager)
            throws IdentityStoreException {

        this.domainManager = domainManager;
        carbonRealmService = CarbonSecurityDataHolder.getInstance().getCarbonRealmService();
        userManager = CarbonSecurityDataHolder.getInstance().getUserManager();

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
                .setAuthorizationStore(carbonRealmService.getAuthorizationStore());

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

        String claimURI = claim.getClaimURI();
        String claimValue = claim.getValue();

        int currentOffset = 0;
        int currentCount = 0;

        for (Domain domain : domainManager.getAllDomains()) {

            for (Map.Entry<String, List<MetaClaimMapping>> metaClaimMappings : domain.getClaimMappings().entrySet()) {

                for (MetaClaimMapping metaClaimMapping : metaClaimMappings.getValue()) {

                    // Required number of users have been retrieved
                    if (currentCount >= length) {
                        break;
                    }

                    if (metaClaimMapping.getMetaClaim().getClaimURI().equals(claimURI)) {

                        IdentityStoreConnector identityStoreConnector =
                                domain.getIdentityStoreConnectorFromId(metaClaimMapping.getIdentityStoreConnectorId());

                        List<User.UserBuilder> userBuilderList =
                                identityStoreConnector.getUserBuilderList(metaClaimMapping.getAttributeName(),
                                        claimValue, offset, length - currentCount);

                        for (User.UserBuilder userBuilder : userBuilderList) {

                            if (currentOffset < offset) {
                                currentOffset++;
                                continue;
                                // Skip all before the offset
                            }

                            try {
                                userBuilder.setUserId(userManager.getUniqueUserId(userBuilder.getUserId(),
                                        identityStoreConnector.getIdentityStoreId()));

                                userBuilder.setIdentityStore(this);
                                userBuilder.setAuthorizationStore(carbonRealmService.getAuthorizationStore());
                                userBuilder.setDomain(domain);

                                users.add(userBuilder.build());

                                currentCount++;
                            } catch (UserManagerException e) {
                                throw new IdentityStoreException("Error retrieving unique user Id for user " +
                                        userBuilder.getUserId(), e);
                            }
                        }
                    }
                }
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

        String claimURI = claim.getClaimURI();
        String claimValue = claim.getValue();


        for (Domain domain : domainManager.getAllDomains()) {

            for (Map.Entry<String, List<MetaClaimMapping>> metaClaimMappings : domain.getClaimMappings().entrySet()) {

                for (MetaClaimMapping metaClaimMapping : metaClaimMappings.getValue()) {

                    if (metaClaimMapping.getMetaClaim().getClaimURI().equals(claimURI)) {

                        IdentityStoreConnector identityStoreConnector =
                                domain.getIdentityStoreConnectorFromId(metaClaimMapping.getIdentityStoreConnectorId());

                        try {
                            Group.GroupBuilder groupBuilder = identityStoreConnector
                                    .getGroupBuilder(metaClaimMapping.getAttributeName(), claimValue);

                            groupBuilder.setDomain(domain);

                            return groupBuilder.build();

                        } catch (GroupNotFoundException e) {
                            if (log.isDebugEnabled()) {
                                log.debug("Group " + claimValue + " not found in identity store connector" +
                                identityStoreConnector.getIdentityStoreId());
                            }
                        }
                    }
                }
            }
        }

        throw new GroupNotFoundException(String
                .format("Group not found for claim %s : %s", claimURI, claimValue));
    }

    @Override
    public List<Group> getGroupsOfUser(String username) throws IdentityStoreException {

        List<Group> groupList = new ArrayList<>();

        Domain domain;

        try {
            domain = domainManager.getDomainFromUserName(username);
        } catch (DomainException e) {
            throw new IdentityStoreException(String
                    .format("Error in getting domain for username %s", username), e);
        }

        Map<String, IdentityStoreConnector> identityStoreConnectorsMap =
                domain.getIdentityStoreConnectorMap();

        for (IdentityStoreConnector identityStoreConnector : identityStoreConnectorsMap.values()) {
            groupList.addAll(identityStoreConnector.getGroupBuildersOfUser(username)
                    .stream()
                    .map(groupBuilder -> groupBuilder
                            .setDomain(domain)
                            .build())
                    .collect(Collectors.toList()));
        }

        return groupList;
    }

    @Override
    public List<User> getUsersOfGroup(String groupID) throws IdentityStoreException {
        // TODO: implement
        return null;
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
            identityStoreConnectorsMap = domainManager
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

    private Domain resolveUserDomain(String attributeValue) throws IdentityStoreException {
        try {
            return domainManager.getDomainFromUserName(attributeValue);
        } catch (DomainException e) {
            throw new IdentityStoreException("Error resolving domain", e);
        }
    }

    @Override
    public List<Claim> getClaims(User user) throws IdentityStoreException {
        List<Claim> claims = new ArrayList<>();
        Domain domain = user.getDomain();

        Map<String, List<MetaClaimMapping>> claimMappings = domain.getClaimMappings();

        Map<String, IdentityStoreConnector> identityStoreConnectors = domain.getIdentityStoreConnectorMap();


        for (Map.Entry<String, IdentityStoreConnector> identityStoreConnectorEntry :
                identityStoreConnectors.entrySet()) {

            String connectorId = identityStoreConnectorEntry.getKey();
            List<MetaClaimMapping> metaClaimMappings = claimMappings.get(connectorId);

            // Create <AttributeName, MetaClaim> map
            Map<String, MetaClaim> attributeMapping = metaClaimMappings.stream()
                    .collect(Collectors.toMap(MetaClaimMapping::getAttributeName, MetaClaimMapping::getMetaClaim));

            IdentityStoreConnector identityStoreConnector = identityStoreConnectorEntry.getValue();

            try {
                String connectorUserId = userManager.getConnectorUserId(user.getUserId(), connectorId);

                List<Attribute> attributeValues = identityStoreConnector.getUserAttributeValues(connectorUserId,
                        new ArrayList<>(attributeMapping.keySet()));
                claims.addAll(buildClaims(attributeValues, attributeMapping));
            } catch (IdentityStoreException | UserManagerException e) {
                throw new IdentityStoreException("Error retrieving claims for user : " + user.getUserId(), e);
            }
        }

        return claims;
    }

    @Override
    public List<Claim> getClaims(User user, List<String> claimURIs) throws IdentityStoreException {
        List<Claim> claims = new ArrayList<>();
        Domain domain = user.getDomain();

        Map<String, List<MetaClaimMapping>> claimMappings = domain.getClaimMappings();

        Map<String, IdentityStoreConnector> identityStoreConnectors = domain.getIdentityStoreConnectorMap();


        for (Map.Entry<String, IdentityStoreConnector> identityStoreConnectorEntry :
                identityStoreConnectors.entrySet()) {

            String connectorId = identityStoreConnectorEntry.getKey();
            List<MetaClaimMapping> metaClaimMappings = claimMappings.get(connectorId);

            // Create <AttributeName, MetaClaim> map
            Map<String, MetaClaim> attributeMapping = metaClaimMappings.stream().
                    filter(metaClaimMapping -> claimURIs.contains(metaClaimMapping.getMetaClaim().getClaimURI()))
                    .collect(Collectors.toMap(MetaClaimMapping::getAttributeName, MetaClaimMapping::getMetaClaim));

            IdentityStoreConnector identityStoreConnector = identityStoreConnectorEntry.getValue();

            try {
                String connectorUserId = userManager.getConnectorUserId(user.getUserId(), connectorId);

                List<Attribute> attributeValues = identityStoreConnector.getUserAttributeValues(connectorUserId,
                        new ArrayList<>(attributeMapping.keySet()));
                claims.addAll(buildClaims(attributeValues, attributeMapping));
            } catch (IdentityStoreException | UserManagerException e) {
                throw new IdentityStoreException("Error retrieving claims for user : " + user.getUserId(), e);
            }
        }

        if (claims.size() < claimURIs.size()) {
            log.warn("Some of the requested claims for the user " + user.getUserId() + " could not be found");
        }

        return claims;
    }

    /**
     * Build Claim Objects from attribute values.
     *
     * @param attributes Attributes with populated values
     * @param attributeMapping Attribute to MetaClaim mappings for the requried claims
     * @return Claims built from attribute values
     */
    private List<Claim> buildClaims(List<Attribute> attributes, Map<String, MetaClaim> attributeMapping) {

        return attributes.stream().map(attribute -> {
            MetaClaim metaClaim = attributeMapping.get(attribute.getAttributeName());
            Claim claim = new Claim();
            claim.setClaimURI(metaClaim.getClaimURI());
            claim.setDialectURI(metaClaim.getDialectURI());
            claim.setValue(attribute.getAttributeValue());
            return claim;
        }).collect(Collectors.toList());
    }
}

