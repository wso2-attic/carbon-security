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

import org.wso2.carbon.security.caas.user.core.claim.MetaClaimMapping;
import org.wso2.carbon.security.caas.user.core.exception.DomainManagerException;
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

    public Domain(String domainName) {

        this.domainName = domainName;
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
     * Add an identity store connector to the map.
     *
     * @param identityStoreConnector   Identity Store connector
     */
    public void addIdentityStoreConnector(IdentityStoreConnector identityStoreConnector) throws DomainManagerException {

        String identityStoreConnectorId = identityStoreConnector.getIdentityStoreId();

        if (this.identityStoreConnectorsMap.containsKey(identityStoreConnectorId)) {

            throw new DomainManagerException(String
                    .format("IdentityStoreConnector %s already exists in the identity store connector map",
                            identityStoreConnectorId));
        }

        this.identityStoreConnectorsMap.put(identityStoreConnectorId, identityStoreConnector);
    }

    /**
     * Get IdentityStoreConnector from identity store connector id.
     *
     * @param identityStoreConnectorId String - IdentityStoreConnectorId
     * @return IdentityStoreConnector
     */
    public IdentityStoreConnector getIdentityStoreConnectorFromId(String identityStoreConnectorId) {

        return this.identityStoreConnectorsMap.get(identityStoreConnectorId);
    }

    /**
     * Get identity store connector map.
     *
     * @return Map<String, IdentityStoreConnector> identityStoreConnectorsMap
     */
    public Map<String, IdentityStoreConnector> getIdentityStoreConnectorMap() {

        return Collections.unmodifiableMap(this.identityStoreConnectorsMap);
    }


    /**
     * Add an credential store connector to the map.
     *
     * @param credentialStoreConnector   Credential Store connector
     */
    public void addCredentialStoreConnector(CredentialStoreConnector credentialStoreConnector)
            throws DomainManagerException {

        String credentialStoreConnectorId = credentialStoreConnector.getCredentialStoreId();

        if (this.credentialStoreConnectorsMap.containsKey(credentialStoreConnectorId)) {

            throw new DomainManagerException(String
                    .format("CredentialStoreConnector %s already exists in the credential store connector map",
                            credentialStoreConnectorId));
        }

        this.credentialStoreConnectorsMap.put(credentialStoreConnectorId, credentialStoreConnector);
    }

    /**
     * Get CredentialStoreConnector from credential store connector id.
     *
     * @param credentialStoreConnectorId String - CredentialStoreConnector ID
     * @return credentialStoreConnector
     */
    public CredentialStoreConnector getCredentialStoreConnectorFromId(String credentialStoreConnectorId) {

        return this.credentialStoreConnectorsMap.get(credentialStoreConnectorId);
    }

    /**
     * Get credential store connector map.
     *
     * @return Map<String, CredentialStoreConnector> credentialStoreConnectorsMap
     */
    public Map<String, CredentialStoreConnector> getCredentialStoreConnectorMap() {

        return Collections.unmodifiableMap(this.credentialStoreConnectorsMap);
    }

    public Map<String, List<MetaClaimMapping>> getClaimMappings() {
        return claimMappings;
    }

    public void setClaimMappings(Map<String, List<MetaClaimMapping>> claimMappings) {
        this.claimMappings = claimMappings;
    }
}
