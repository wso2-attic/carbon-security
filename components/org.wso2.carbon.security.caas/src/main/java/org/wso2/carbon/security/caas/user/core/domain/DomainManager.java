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
import org.wso2.carbon.security.caas.user.core.bean.User;

import java.util.List;

/**
 * Domain manager.
 */
public interface DomainManager {

    /**
     * Get the domain from the name.
     * @param domainName Name of the domain.
     * @return Domain.
     */
    Domain getDomainFromName(String domainName);

    /**
     * Get users for a specific domain.
     *
     * @param domainName Name of the domain
     * @return List of users in a specific domain
     */
    List<User> getUsersForDomainName(String domainName);

    /**
     * Register new Identity Store Connector.
     * @param domainName Name of the domain.
     * @param identityStoreId Identity Store Id.
     */
    void registerNewIdentityStore(String domainName, String identityStoreId);

    /**
     * Register new Identity Store Connector.
     * @param domainName Name of the domain.
     * @param credentialStoreId Credential Store Id.
     */
    void registerNewCredentialStore(String domainName, String credentialStoreId);
}
