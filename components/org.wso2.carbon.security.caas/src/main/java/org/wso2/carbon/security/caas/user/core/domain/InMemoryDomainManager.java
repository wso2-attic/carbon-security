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
import org.wso2.carbon.security.caas.user.core.config.StoreConfig;
import org.wso2.carbon.security.caas.user.core.exception.CredentialStoreException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;

import java.util.HashMap;
import java.util.Map;

/**
 * Domain manager.
 */
public class InMemoryDomainManager implements DomainManager {

    /**
     * Domain name to domain mapping.
     */
    private Map<String, Domain> domainNameToDomain = new HashMap<>();

    @Override
    public Domain getDomainFromName(String domainName) {

        return this.domainNameToDomain.get(domainName);
    }

    @Override
    public void addDomain(String domainName, StoreConfig storeConfig)
            throws CredentialStoreException, IdentityStoreException {

        Domain domain = new Domain(domainName, storeConfig);

        this.domainNameToDomain.put(domainName, domain);
    }

    // TODO <VIDURA> Add implementation
    @Override
    public Domain getDomainFromUserName(String username) {
        return null;
    }

}
