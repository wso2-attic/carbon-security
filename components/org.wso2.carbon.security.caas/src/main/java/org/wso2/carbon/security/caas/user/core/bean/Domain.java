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

package org.wso2.carbon.security.caas.user.core.bean;

import org.wso2.carbon.security.caas.user.core.claim.Claim;
import org.wso2.carbon.security.caas.user.core.claim.MetaClaimMapping;
import org.wso2.carbon.security.caas.user.core.exception.DomainException;
import org.wso2.carbon.security.caas.user.core.store.connector.CredentialStoreConnector;
import org.wso2.carbon.security.caas.user.core.store.connector.IdentityStoreConnector;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Represents a domain.
 */
public class Domain {

    /**
     * Mapping between IdentityStoreConnector ID and IdentityStoreConnector
     */
    private Map<String, IdentityStoreConnector> identityStoreConnectorsMap = new HashMap<>();

    /**
     * Mapping between CredentialStoreConnector ID and CredentialStoreConnector
     */
    private Map<String, CredentialStoreConnector> credentialStoreConnectorsMap = new HashMap<>();

    /**
     * Mapping between IdentityStoreConnector ID and MetaClaimMapping
     */
    private Map<String, List<MetaClaimMapping>> claimMappings = new HashMap<>();

    /**
     * Name of the domain.
     */
    private String domainName;

    /**
     * Priority of the domain.
     * Highest priority for domain is 1
     * Domain priority value should be greater than 0
     */
    private int domainPriority;

    public Domain(String domainName, int domainPriority) throws DomainException {

        if (domainPriority < 1) {
            throw new DomainException("Domain priority value should be greater than 0");
        }

        this.domainName = domainName;
        this.domainPriority = domainPriority;
    }

    /**
     * Get the domain name.
     *
     * @return String - domain name
     */
    public String getDomainName() {
        return domainName;
    }

    /**
     * Get the priority of the domain.
     *
     * @return integer - domain priority
     */
    public int getDomainPriority() {

        return domainPriority;
    }

    /**
     * Add an identity store connector to the map.
     *
     * @param identityStoreConnector Identity Store connector
     */
    public void addIdentityStoreConnector(IdentityStoreConnector identityStoreConnector)
            throws DomainException {

        String identityStoreConnectorId = identityStoreConnector.getIdentityStoreId();

        if (identityStoreConnectorsMap.containsKey(identityStoreConnectorId)) {

            throw new DomainException(String
                    .format("IdentityStoreConnector %s already exists in the identity store connector map",
                            identityStoreConnectorId));
        }

        identityStoreConnectorsMap.put(identityStoreConnectorId, identityStoreConnector);
    }

    /**
     * Get IdentityStoreConnector from identity store connector id.
     *
     * @param identityStoreConnectorId String - IdentityStoreConnectorId
     * @return IdentityStoreConnector
     */
    public IdentityStoreConnector getIdentityStoreConnectorFromId(String identityStoreConnectorId) {

        return identityStoreConnectorsMap.get(identityStoreConnectorId);
    }

    /**
     * Get identity store connector map.
     *
     * @return Map of connectorId to IdentityStoreConnector
     */
    public Map<String, IdentityStoreConnector> getIdentityStoreConnectorMap() {

        return Collections.unmodifiableMap(identityStoreConnectorsMap);
    }

    /**
     * Add an credential store connector to the map.
     *
     * @param credentialStoreConnector Credential Store connector
     * @throws DomainException domain exception
     */
    public void addCredentialStoreConnector(CredentialStoreConnector credentialStoreConnector)
            throws DomainException {

        String credentialStoreConnectorId = credentialStoreConnector.getCredentialStoreId();

        if (credentialStoreConnectorsMap.containsKey(credentialStoreConnectorId)) {

            throw new DomainException(String
                    .format("CredentialStoreConnector %s already exists in the credential store connector map",
                            credentialStoreConnectorId));
        }

        credentialStoreConnectorsMap.put(credentialStoreConnectorId, credentialStoreConnector);
    }

    /**
     * Get CredentialStoreConnector from credential store connector id.
     *
     * @param credentialStoreConnectorId String - CredentialStoreConnector ID
     * @return credentialStoreConnector
     */
    public CredentialStoreConnector getCredentialStoreConnectorFromId(String credentialStoreConnectorId) {

        return credentialStoreConnectorsMap.get(credentialStoreConnectorId);
    }

    /**
     * Get credential store connector map.
     *
     * @return Map of connector Id to CredentialStoreConnector
     */
    public Map<String, CredentialStoreConnector> getCredentialStoreConnectorMap() {

        return Collections.unmodifiableMap(credentialStoreConnectorsMap);
    }

    /**
     * Checks weather a certain claim exists in the domain claim mappings.
     *
     * @param claim Claim
     * @return is claim belong to domain
     */
    public boolean isClaimBelongToDomain(Claim claim) {

        String claimURI = claim.getClaimURI();

        return claimMappings.values().stream()
                .anyMatch(list -> list.stream().filter(metaClaimMapping ->
                        claimURI.equals(metaClaimMapping.getMetaClaim().getClaimURI()))
                        .findFirst().isPresent());
    }

    /**
     * Get claim mappings for an identity store id.
     *
     * @return Map of claimURI to List of MetaClaimMapping
     */
    public Map<String, List<MetaClaimMapping>> getClaimMappings() {

        return claimMappings;
    }

    /**
     * Set claim mappings for an identity store id.
     *
     * @param claimMappings Map<String, List<MetaClaimMapping>> claim mappings
     */
    public void setClaimMappings(Map<String, List<MetaClaimMapping>> claimMappings) {

        this.claimMappings = claimMappings;
    }
}
