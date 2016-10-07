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

/**
 * Claim Mapping.
 */
public class MetaClaimMapping {

    /**
     * Meta metaClaim instance.
     */
    private MetaClaim metaClaim;

    private String identityStoreConnectorId;

    private String attributeName;

    public MetaClaimMapping(MetaClaim metaClaim, String identityStoreConnectorId, String attributeName) {
        this.metaClaim = metaClaim;
        this.identityStoreConnectorId = identityStoreConnectorId;
        this.attributeName = attributeName;
    }

    public MetaClaim getMetaClaim() {
        return metaClaim;
    }

    public void setMetaClaim(MetaClaim claim) {
        this.metaClaim = claim;
    }

    public String getIdentityStoreConnectorId() {
        return identityStoreConnectorId;
    }

    public void setIdentityStoreConnectorId(String identityStoreConnectorId) {
        this.identityStoreConnectorId = identityStoreConnectorId;
    }

    public String getAttributeName() {
        return attributeName;
    }

    public void setAttributeName(String attributeName) {
        this.attributeName = attributeName;
    }
}
