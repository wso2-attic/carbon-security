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

package org.wso2.carbon.security.boot;

import org.osgi.framework.BundleContext;
import org.osgi.framework.InvalidSyntaxException;
import org.osgi.framework.ServiceReference;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

/**
 * <p>
 * Proxy login module which act as a wrapper for real login modules. Two properties must be set from the javax
 * .security.auth.login.Configuration implementation, the name of the login module and bundle id to be used to load it.
 * <p/>
 * This class MUST be available from all modules.
 * </p>
 */
public class ProxyLoginModule implements LoginModule {

    public static final String PROPERTY_LOGIN_MODULE = "LOGIN_MODULE";

    private static BundleContext bundleContext;

    private LoginModule instance = null;

    public static void init(BundleContext context) {
        bundleContext = context;
    }

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState,
                           Map<String, ?> options) {

        if (bundleContext == null) {
            throw new IllegalStateException("ProxyLoginModule not initialized.");
        }

        Map<String, ?> updatedOptions = new HashMap<>(options);

        String module = (String) updatedOptions.remove(PROPERTY_LOGIN_MODULE);
        if (module == null) {
            throw new IllegalStateException("Option " + PROPERTY_LOGIN_MODULE + " must be set from the " +
                                            "javax.security.auth.login.Configuration implementation");
        }

        try {
            Collection<ServiceReference<LoginModule>> serviceReferences = bundleContext.getServiceReferences
                    (LoginModule.class, "(&(login.module.class.name=" + module + ")(service.scope=prototype))");
            if (serviceReferences != null) {
                serviceReferences.forEach(
                        serviceReference -> instance = bundleContext.getServiceObjects(serviceReference).getService()
                );
            }
        } catch (InvalidSyntaxException e) {
            throw new IllegalStateException("Unable to find login module service reference for module " + module);
        }

        if (instance == null) {
            throw new IllegalStateException("Unable to find login module " + module);
        }

        instance.initialize(subject, callbackHandler, sharedState, updatedOptions);
    }

    @Override
    public boolean login() throws LoginException {
        return instance.login();
    }

    @Override
    public boolean commit() throws LoginException {
        return instance.commit();
    }

    @Override
    public boolean abort() throws LoginException {
        return instance.abort();
    }

    @Override
    public boolean logout() throws LoginException {
        return instance.logout();
    }
}
