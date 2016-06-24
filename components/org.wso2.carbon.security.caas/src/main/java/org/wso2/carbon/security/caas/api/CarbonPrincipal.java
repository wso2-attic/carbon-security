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

package org.wso2.carbon.security.caas.api;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.security.caas.user.core.bean.Action;
import org.wso2.carbon.security.caas.user.core.bean.Permission;
import org.wso2.carbon.security.caas.user.core.bean.Resource;
import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.exception.AuthorizationStoreException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;

import java.security.Principal;
import java.util.Objects;

/**
 * This class {@code CarbonPrincipal} is the principal representation of the carbon platform.
 * This is an implementation of {@code Principal}.
 *
 * @since 1.0.0
 */
public class CarbonPrincipal implements Principal {

    private static final Logger log = LoggerFactory.getLogger(CarbonPrincipal.class);

    private User user;

    public CarbonPrincipal() {

    }

    public CarbonPrincipal(User user) {
        this.user = user;
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(this);
    }

    @Override
    public boolean equals(Object obj) {
        return this == obj;
    }

    @Override
    public String getName() {
        return this.user.getUserName();
    }

    public User getUser() {
        return user;
    }

    /**
     * Checks whether the current principal has a given {@code CarbonPermission}.
     *
     * @param carbonPermission CarbonPermission which needs to be checked with principal instance.
     * @return true if authorized.
     */
    public boolean isAuthorized(CarbonPermission carbonPermission) {

        String resourceDomain = carbonPermission.getName()
                .substring(0, carbonPermission.getName().indexOf(Resource.DELIMITER));
        String resourceId = carbonPermission.getName()
                .substring(carbonPermission.getName().indexOf(Resource.DELIMITER));

        String actionDomain = carbonPermission.getActions()
                .substring(0, carbonPermission.getActions().indexOf(Action.DELIMITER));
        String actionName = carbonPermission.getActions()
                .substring(carbonPermission.getActions().indexOf(Action.DELIMITER));

        Resource resource = new Resource(resourceDomain, resourceId);
        Action action = new Action(actionDomain, actionName);

        try {
            return user.isAuthorized(new Permission(resource, action));
        } catch (AuthorizationStoreException | IdentityStoreException e) {
            log.error("Access denied for permission " + carbonPermission.getName() + " for user " + user.getUserId()
                      + " due to a server error", e);
            return false;
        }
    }
}
