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

import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.exception.ClaimManagerException;

import java.util.List;

/**
 * This is the interface to manage claims in the system.
 */
public interface ClaimManager {

    /**
     * Get all claims of a user.
     *
     * @param user The user to retrieve claims for
     * @return List of claims
     * @throws ClaimManagerException
     */
    List<Claim> getClaims(User user) throws ClaimManagerException;

    /**
     * Get all claims of a user for given URIs.
     *
     * @param user The user to retrieve claims for
     * @param claimURIs List of claimURIs to retrieve claims for
     * @return List of claims
     * @throws ClaimManagerException
     */
    List<Claim> getClaims(User user, List<String> claimURIs) throws ClaimManagerException;
}
