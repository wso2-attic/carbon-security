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

package org.wso2.carbon.security.usercore.util;

import org.wso2.carbon.security.usercore.constant.UserStoreConstants;

/**
 * User core utils.
 */
public class UserCoreUtil {

    public static final String DOMAIN_SEPARATOR = "/";

    /**
     * Returns only username
     *
     * @param username username with domain name or only username
     * @return
     */
    public String getUserName(String username) {
        if (username.contains(DOMAIN_SEPARATOR)) {
            return username.substring(username.indexOf(DOMAIN_SEPARATOR) + 1);
        }
        return username;
    }

    public String getUserStoreName(String username) {
        if (username.contains(DOMAIN_SEPARATOR)) {
            return username.substring(0, username.indexOf(DOMAIN_SEPARATOR));
        }
        return UserStoreConstants.PRIMARY;
    }

    public String appendDomainName(String username, String domainName) {
        return domainName + DOMAIN_SEPARATOR + username;
    }
}
