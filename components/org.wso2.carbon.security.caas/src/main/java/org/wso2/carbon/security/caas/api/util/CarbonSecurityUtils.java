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

package org.wso2.carbon.security.caas.api.util;

import org.osgi.framework.BundleContext;
import org.osgi.framework.InvalidSyntaxException;
import org.osgi.framework.ServiceReference;
import org.wso2.carbon.security.caas.api.CarbonCallbackHandler;
import org.wso2.carbon.security.caas.api.exception.CarbonSecurityServerException;
import org.wso2.carbon.security.caas.api.model.User;
import org.wso2.carbon.security.caas.api.model.UsersFile;
import org.wso2.carbon.security.caas.internal.CarbonSecurityDataHolder;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Carbon Security Utils.
 *
 * @since 1.0.0
 */
public class CarbonSecurityUtils {

    private static final String USERS_CONFIG_ABSOLUTE_LOCATION =
            CarbonSecurityConstants.getCarbonHomeDirectory().getFileName() +
                                                           CarbonSecurityConstants.USERS_CONFIG_LOCATION;

    public static List<CarbonCallbackHandler> getCallbackHandlers(String supportedLoginModule) {

        List<CarbonCallbackHandler> callbackHandlers = new ArrayList<>();
        BundleContext bundleContext = CarbonSecurityDataHolder.getInstance().getBundleContext();

        try {
            Collection<ServiceReference<CarbonCallbackHandler>> serviceReferences = bundleContext.getServiceReferences
                    (CarbonCallbackHandler.class, "(&(" + CarbonCallbackHandler.SUPPORTED_LOGIN_MODULE + "=" +
                                                supportedLoginModule + ")(service.scope=prototype))");
            if (serviceReferences != null) {
                serviceReferences.forEach(
                        serviceReference -> callbackHandlers.add(bundleContext.getServiceObjects(serviceReference)
                                                                         .getService())
                );
            }
        } catch (InvalidSyntaxException e) {
            throw new IllegalStateException("Invalid syntax found while searching Callback handler " +
                                            supportedLoginModule);
        }
        return callbackHandlers;
    }

    private static UsersFile getUsers() throws CarbonSecurityServerException {
        return FileUtil.readConfigFile(USERS_CONFIG_ABSOLUTE_LOCATION, UsersFile.class);
    }

    public static User getUser(String username) throws CarbonSecurityServerException {
        UsersFile users = CarbonSecurityUtils.getUsers();
        for (User user : users.getUsers()) {
            if (user.getUsername().equals(username)) {
                return user;
            }
        }
        return null;
    }

    private CarbonSecurityUtils() {

    }

}
