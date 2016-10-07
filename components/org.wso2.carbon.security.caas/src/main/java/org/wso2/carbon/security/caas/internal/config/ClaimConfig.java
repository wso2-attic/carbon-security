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

package org.wso2.carbon.security.caas.internal.config;

import org.wso2.carbon.security.caas.user.core.claim.MetaClaim;

import java.util.Map;

/**
 * Claim Config.
 */
public class ClaimConfig {

    private String claimManager;

    private Map<String, MetaClaim> metaClaims;

    public ClaimConfig() {

    }

    public ClaimConfig(String claimManager, Map<String, MetaClaim> metaClaims) {
        this.claimManager = claimManager;
        this.metaClaims = metaClaims;
    }

    public String getClaimManager() {
        return claimManager;
    }

    public void setClaimManager(String claimManager) {
        this.claimManager = claimManager;
    }

    public Map<String, MetaClaim> getMetaClaims() {
        return metaClaims;
    }

    public void setMetaClaims(Map<String, MetaClaim> metaClaims) {
        this.metaClaims = metaClaims;
    }
}
