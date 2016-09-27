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
import org.wso2.carbon.security.caas.user.core.exception.StoreException;

import java.util.HashMap;
import java.util.Map;

/**
 * Domain manager.
 */
public class InMemoryDomainManager implements DomainManager {

    private Map<String, Domain> domainFromId = new HashMap<>();
    private Map<String, String> domainNameToId = new HashMap<>();

    @Override
    public Domain getDomainFromName(String domainName) {

        String domainId = domainNameToId.get(domainName);
        return domainFromId.get(domainId);
    }

    @Override
    public void registerNewIdentityStore(String domainName, String identityStoreId) {

        Domain domain = domainFromId.get(domainNameToId.get(domainName));

        if (domain == null) {
            throw new StoreException("No domain presents for the given domain name.");
        }

        domain.getIdentityStoreIdList().add(identityStoreId);
    }

    @Override
    public void registerNewCredentialStore(String domainName, String credentialStoreId) {

        Domain domain = domainFromId.get(domainNameToId.get(domainName));

        if (domain == null) {
            throw new StoreException("No domain presents for the given domain name.");
        }

        domain.getIdentityStoreIdList().add(credentialStoreId);
    }
}
