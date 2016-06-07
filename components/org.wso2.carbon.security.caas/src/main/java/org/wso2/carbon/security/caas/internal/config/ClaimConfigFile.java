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

import java.util.List;

/**
 * Claim Config mapper class.
 */
public class ClaimConfigFile {

    private String claimManager;

    private String dialectURI;

    private List<ClaimEntry> claims;

    public String getClaimManager() {
        return claimManager;
    }

    public void setClaimManager(String claimManager) {
        this.claimManager = claimManager;
    }

    public String getDialectURI() {
        return dialectURI;
    }

    public void setDialectURI(String dialectURI) {
        this.dialectURI = dialectURI;
    }

    public List<ClaimEntry> getClaims() {
        return claims;
    }

    public void setClaims(List<ClaimEntry> claims) {
        this.claims = claims;
    }
}
