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

package org.wso2.carbon.security.caas.user.core.claim;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.security.caas.internal.CarbonSecurityDataHolder;
import org.wso2.carbon.security.caas.user.core.bean.Attribute;
import org.wso2.carbon.security.caas.user.core.bean.Domain;
import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.exception.ClaimManagerException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.exception.UserManagerException;
import org.wso2.carbon.security.caas.user.core.store.connector.IdentityStoreConnector;
import org.wso2.carbon.security.caas.user.core.user.UserManager;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * InMemory Claim Manager.
 */
public class InMemoryClaimManager implements ClaimManager {

    private static final Logger log = LoggerFactory.getLogger(InMemoryClaimManager.class);

    /**
     * UserManager which is used to manage globally unique user Id.
     */
    private UserManager userManager;


    /**
     * Initialize claim manager with user manager reference.
     */
    public InMemoryClaimManager() {
        userManager = CarbonSecurityDataHolder.getInstance().getUserManager();
    }

    @Override
    public List<Claim> getClaims(User user) throws ClaimManagerException {
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
                throw new ClaimManagerException("Error retrieving claims for user : " + user.getUserId(), e);
            }
        }

        return claims;
    }

    @Override
    public List<Claim> getClaims(User user, List<String> claimURIs) throws ClaimManagerException {
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
                throw new ClaimManagerException("Error retrieving claims for user : " + user.getUserId(), e);
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
