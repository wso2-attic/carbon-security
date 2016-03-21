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

import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.util.HashMap;
import java.util.Map;

/**
 * <p>
 * Proxy login module which act as a wrapper for real login modules. Two properties must be set from the javax
 * .security.auth.login.Configuration implementation, the name of the login module and bundle id to be used to load it.
 *
 * This class MUST be available from all modules.
 * </p>
 */
public class ProxyLoginModule implements LoginModule {

    public static final String PROPERTY_LOGIN_MODULE = "LOGIN_MODULE";

    public static final String PROPERTY_BUNDLE_ID = "BUNDLE_ID";

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

        String bundleId = (String) updatedOptions.remove(PROPERTY_BUNDLE_ID);
        if (bundleId == null) {
            throw new IllegalStateException("Option " + PROPERTY_BUNDLE_ID + " must be set to the name " +
                                            "javax.security.auth.login.Configuration implementation");
        }

        Bundle bundle = bundleContext.getBundle(Long.parseLong(bundleId));
        if (bundle == null) {
            throw new IllegalStateException("No bundle found for id " + bundleId);
        }

        try {
            instance = (LoginModule) bundle.loadClass(module).newInstance();
        } catch (InstantiationException | IllegalAccessException e) {
            throw new IllegalStateException("Failed to instantiate " + module, e);
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException("Unable to find login module " + module + " of the bundle " + bundleId, e);
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
