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

import java.util.List;
import java.util.Map;

/**
 * This is the interface to manage claims in the system.
 */
public interface ClaimManager {

    /**
     * Initialize Claim Manager.
     *
     * @param metaClaimMapping Meta claim mappings.
     * @throws ClaimManagerException Claim Manager initialization failure.
     */
    void init(Map<String, MetaClaimMapping> metaClaimMapping) throws ClaimManagerException;

    /**
     * Get all meta claim mappings.
     *
     * @return MetaClaimMapping list.
     * @throws ClaimManagerException Claim Manager failure.
     */
    List<MetaClaimMapping> getAllMetaClaimMappings() throws ClaimManagerException;

    /**
     * Get meta claim mappings for an identity store.
     *
     * @param identityStoreId Identity store id.
     * @return Identity store specific meta claim list.
     * @throws ClaimManagerException Claim Manager failure.
     */
    List<IdnStoreMetaClaimMapping> getMetaClaimMappingsByIdentityStoreId(String identityStoreId)
            throws ClaimManagerException;

    /**
     * Get requested meta claim mappings for an identity store.
     *
     * @param identityStoreId Identity store id.
     * @param claimURIs Requested claim URIs.
     * @return Requested identity store specific meta claim list.
     * @throws ClaimManagerException Claim Manager failure.
     */
    List<IdnStoreMetaClaimMapping> getMetaClaimMappingsByIdentityStoreId(String identityStoreId,
            List<String> claimURIs) throws ClaimManagerException;
}
