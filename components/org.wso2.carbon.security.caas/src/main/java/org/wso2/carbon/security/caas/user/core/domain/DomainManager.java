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

package org.wso2.carbon.security.caas.user.core.domain;

import org.wso2.carbon.security.caas.user.core.bean.Domain;
import org.wso2.carbon.security.caas.user.core.exception.DomainException;
import org.wso2.carbon.security.caas.user.core.store.connector.CredentialStoreConnector;
import org.wso2.carbon.security.caas.user.core.store.connector.IdentityStoreConnector;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;

/**
 * Domain manager.
 */
public class DomainManager {

    /**
     * Mapping between domain priority and domain name to domain.
     * Map<String, Domain> maps between domain map to domain instance
     * Retrieval and insertion - O(log n)
     */
    private TreeMap<Integer, Map<String, Domain>> domainPriorityToDomainMap = new TreeMap<>();

    /**
     * Mapping between all domain names and domain instances.
     */
    private Map<String, Domain> allDomainNameToDomainMap = new HashMap<>();

    /**
     * List of domains ordered by their priority.
     */
    private List<Domain> orderedDomainList;

    /**
     * Get the domain from the name.
     *
     * @param domainName Name of the domain.
     * @return Domain.
     * @throws DomainException domain exception
     */
    public Domain getDomainFromDomainName(String domainName) throws DomainException {

        Domain domain = allDomainNameToDomainMap.get(domainName);

        if (domain == null) {
            throw new DomainException(String.format("Domain %s was not found", domainName));
        }

        return domain;
    }

    /**
     * Get the list of domains which belongs to a certain priority.
     *
     * @param priority domain priority
     * @return Map of domain name to Domain
     */
    public Map<String, Domain> getDomainsFromPriority(int priority) throws DomainException {

        Map<String, Domain> domainNameToDomainMap = domainPriorityToDomainMap.get(priority);

        if (domainNameToDomainMap == null) {
            throw new DomainException(String.format("Domain for priority %d not found", priority));
        }

        return domainNameToDomainMap;
    }

    /**
     * Add a domain to the mapping
     *
     * @param domain Domain object
     */
    public void addDomain(Domain domain) throws DomainException {

        String domainName = domain.getDomainName();
        int domainPriority = domain.getDomainPriority();

        if (allDomainNameToDomainMap.containsKey(domainName)) {
            throw new DomainException(String
                    .format("Domain %s already exists in the domain map", domainName));
        }

        if (!domainPriorityToDomainMap.containsKey(domainPriority)) {
            domainPriorityToDomainMap.put(domainPriority, new HashMap<>());
        }

        // Add to domain priority list and domain name list
        domainPriorityToDomainMap.get(domain.getDomainPriority()).put(domainName, domain);
        allDomainNameToDomainMap.put(domainName, domain);

    }

    /**
     * Get IdentityStoreConnector from identity store connector id.
     *
     * @param identityStoreConnectorId String - IdentityStoreConnectorId
     * @param domainName               Name of the domain which the connector instance belongs
     * @return IdentityStoreConnector
     * @throws DomainException Domain exception
     */
    public IdentityStoreConnector getIdentityStoreConnector(
            String identityStoreConnectorId, String domainName) throws DomainException {

        Domain domain = getDomainFromDomainName(domainName);

        IdentityStoreConnector identityStoreConnector = domain.getIdentityStoreConnectorFromId
                (identityStoreConnectorId);

        if (identityStoreConnector == null) {
            throw new DomainException(String
                    .format("IdentityStoreConnector %s was not found", identityStoreConnectorId));
        }

        return identityStoreConnector;
    }

    /**
     * Get identity store connector map.
     *
     * @param domainName Name of the domain which the connector instances belong
     * @return Map of connector Id to IdentityStoreConnector
     * @throws DomainException DomainException
     */
    public Map<String, IdentityStoreConnector> getIdentityStoreConnectorMapForDomain(
            String domainName) throws DomainException {

        return getDomainFromDomainName(domainName)
                .getIdentityStoreConnectorMap();

    }

    /**
     * Add an credential store connector to the map of a domain.
     *
     * @param credentialStoreConnector Credential Store connector
     * @param domainName               Name of the domain to add the connector
     */
    public void addCredentialStoreConnectorToDomain(
            CredentialStoreConnector credentialStoreConnector,
            String domainName) throws DomainException {

        Domain domain = getDomainFromDomainName(domainName);

        domain.addCredentialStoreConnector(credentialStoreConnector);
    }

    /**
     * Get CredentialStoreConnector from credential store connector id.
     *
     * @param credentialStoreConnectorId String - CredentialStoreConnectorId
     * @param domainName                 Name of the domain which the connector instance belongs
     * @return CredentialStoreConnector
     * @throws DomainException DomainException
     */
    public CredentialStoreConnector getCredentialStoreConnector(
            String credentialStoreConnectorId, String domainName) throws DomainException {

        Domain domain = getDomainFromDomainName(domainName);

        CredentialStoreConnector credentialStoreConnector = domain
                .getCredentialStoreConnectorFromId(credentialStoreConnectorId);

        if (credentialStoreConnector == null) {
            throw new DomainException(String
                    .format("credentialStoreConnector %s was not found", credentialStoreConnectorId));
        }

        return credentialStoreConnector;
    }

    /**
     * Get credential store connector map.
     *
     * @param domainName Name of the domain which the connector instances belong
     * @return Map of connector Id to CredentialStoreConnector
     * @throws DomainException Domain exception
     */
    public Map<String, CredentialStoreConnector> getCredentialStoreConnectorMapForDomain(
            String domainName) throws DomainException {

        return getDomainFromDomainName(domainName)
                .getCredentialStoreConnectorMap();
    }

    /**
     * Get all available domains.
     * Domains are returned as a list ordered by their priority highest to lowest.
     *
     * @return A list of domains ordered by their priority
     */
    public List<Domain> getAllDomains() {

        if (orderedDomainList == null) {
            orderedDomainList = allDomainNameToDomainMap.values().stream()
                    .sorted((f1, f2) -> Integer.compare(f2.getDomainPriority(), f1.getDomainPriority()))
                    .collect(Collectors.toList());
        }

        return orderedDomainList;
    }

}
