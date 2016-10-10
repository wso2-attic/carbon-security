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
import org.wso2.carbon.security.caas.user.core.exception.DomainManagerException;
import org.wso2.carbon.security.caas.user.core.store.connector.IdentityStoreConnector;

import java.util.Map;

/**
 * Domain manager.
 */
public interface DomainManager {

    /**
     * Get the domain from the name.
     *
     * @param domainName Name of the domain.
     * @return Domain.
     * @throws DomainManagerException
     */
    Domain getDomainFromName(String domainName) throws DomainManagerException;

    /**
     * Add a domain to the mapping
     *
     * @param domain Domain object
     */
    void addDomain(Domain domain) throws DomainManagerException;

    /**
     * Get the domain instance when a user name is given.
     *
     * @param username String username
     * @return Domain instance for which the user belongs
     */
    Domain getDomainFromUserName(String username);

    /**
     * Create the default domain instance.
     */
    void createDefaultDomain() throws DomainManagerException;

    /**
     * Get the default domain instance.
     *
     * @return Default domain instance
     * @throws DomainManagerException
     */
    Domain getDefaultDomain() throws DomainManagerException;

    /**
     * Get IdentityStoreConnector from identity store connector id.
     *
     * @param identityStoreConnectorId String - IdentityStoreConnectorId
     * @param domainName               Name of the domain which the connector instance belongs
     * @return IdentityStoreConnector
     * @throws DomainManagerException
     */
    IdentityStoreConnector getIdentityStoreConnector(
            String identityStoreConnectorId, String domainName) throws DomainManagerException;

    /**
     * Get identity store connector map.
     *
     * @param domainName Name of the domain which the connector instances belong
     * @return Map<String, IdentityStoreConnector> identityStoreConnectorsMap
     * @throws DomainManagerException
     */
    Map<String, IdentityStoreConnector> getIdentityStoreConnectorMapForDomain(
            String domainName) throws DomainManagerException;
}
