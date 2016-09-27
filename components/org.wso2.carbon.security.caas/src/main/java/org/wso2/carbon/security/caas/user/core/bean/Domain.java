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

package org.wso2.carbon.security.caas.user.core.bean;

import java.util.List;

/**
 * Represents a domain.
 */
public class Domain {

    private String domainId;
    private String domainName;

    private List<String> identityStoreIdList;
    private List<String> credentialStoreIdList;

    public Domain(String domainId, String domainName) {
        this.domainId = domainId;
        this.domainName = domainName;
    }

    public List<String> getIdentityStoreIdList() {
        return identityStoreIdList;
    }

    public List<String> getCredentialStoreIdList() {
        return credentialStoreIdList;
    }

    public String getDomainId() {
        return domainId;
    }

    public void setDomainId(String domainId) {
        this.domainId = domainId;
    }

    public String getDomainName() {
        return domainName;
    }

    public void setDomainName(String domainName) {
        this.domainName = domainName;
    }
}
