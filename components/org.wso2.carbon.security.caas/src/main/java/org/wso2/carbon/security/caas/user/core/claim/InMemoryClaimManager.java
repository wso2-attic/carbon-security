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

import org.wso2.carbon.security.caas.user.core.exception.ClaimManagerException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * InMemory Claim Manager.
 */
public class InMemoryClaimManager implements ClaimManager {

    private Map<String, MetaClaimMapping> metaClaimMappingMap;

    @Override
    public void init(Map<String, MetaClaimMapping> metaClaimMappingMap) throws ClaimManagerException {
        this.metaClaimMappingMap = metaClaimMappingMap;
    }

    @Override
    public List<MetaClaimMapping> getAllMetaClaimMappings() {

        if (metaClaimMappingMap.isEmpty()) {
            return Collections.emptyList();
        }

        return new ArrayList<>(metaClaimMappingMap.values());
    }

    @Override
    public List<IdnStoreMetaClaimMapping> getMetaClaimMappingsByIdentityStoreId(String identityStoreId)
            throws ClaimManagerException {

        if (metaClaimMappingMap == null || metaClaimMappingMap.isEmpty()) {
            return Collections.emptyList();
        }

        return metaClaimMappingMap.values().stream()
                .filter(claimMapping -> claimMapping.getAttributeNamesMap().containsKey(identityStoreId))
                .map(claimMapping -> new IdnStoreMetaClaimMapping(claimMapping.getMetaClaim(), claimMapping
                        .getAttributeName(identityStoreId)))
                .collect(Collectors.toList());
    }

    @Override
    public List<IdnStoreMetaClaimMapping> getMetaClaimMappingsByIdentityStoreId(String identityStoreId, List<String>
            claimURIs) throws ClaimManagerException {

        if (metaClaimMappingMap == null || metaClaimMappingMap.isEmpty() || claimURIs == null || claimURIs.isEmpty()) {
            return Collections.emptyList();
        }

        return claimURIs.stream()
                .filter(claimURI -> metaClaimMappingMap.containsKey(claimURI))
                .map(claimURI -> metaClaimMappingMap.get(claimURI))
                .filter(metaClaimMapping -> metaClaimMapping.getAttributeNamesMap().containsKey(identityStoreId))
                .map(claimMapping -> new IdnStoreMetaClaimMapping(claimMapping.getMetaClaim(), claimMapping
                        .getAttributeName(identityStoreId)))
                .collect(Collectors.toList());
    }
}
