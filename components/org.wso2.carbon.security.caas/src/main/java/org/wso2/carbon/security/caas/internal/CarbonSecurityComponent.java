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

package org.wso2.carbon.security.caas.internal;

import org.osgi.framework.BundleContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.caching.CarbonCachingService;
import org.wso2.carbon.kernel.startupresolver.RequiredCapabilityListener;
import org.wso2.carbon.security.caas.api.CarbonCallbackHandler;
import org.wso2.carbon.security.caas.api.CarbonJAASConfiguration;
import org.wso2.carbon.security.caas.api.module.UsernamePasswordLoginModule;
import org.wso2.carbon.security.caas.api.util.CarbonSecurityConstants;
import org.wso2.carbon.security.caas.boot.ProxyLoginModule;
import org.wso2.carbon.security.caas.internal.osgi.UserNamePasswordLoginModuleFactory;
import org.wso2.carbon.security.caas.internal.osgi.UsernamePasswordCallbackHandlerFactory;

import java.util.Hashtable;
import java.util.Map;
import javax.security.auth.spi.LoginModule;

/**
 * OSGi service component which handle authentication and authorization.
 *
 * @since 1.0.0
 */
@Component(
        name = "org.wso2.carbon.security.caas.internal.CarbonSecurityComponent",
        immediate = true,
        property = {
                "componentName=wso2-caas"
        }
)
public class CarbonSecurityComponent implements RequiredCapabilityListener {

    private static final Logger log = LoggerFactory.getLogger(CarbonSecurityComponent.class);

    @Activate
    public void registerCarbonSecurityProvider(BundleContext bundleContext) {

        CarbonSecurityDataHolder.getInstance().setBundleContext(bundleContext);
        initAuthenticationConfigs(bundleContext);
    }

    @Deactivate
    public void unregisterCarbonSecurityProvider(BundleContext bundleContext) {

        log.info("Carbon-Security bundle deactivated successfully.");
    }

    @Reference(
            name = "carbon.caching.service",
            service = CarbonCachingService.class,
            cardinality = ReferenceCardinality.OPTIONAL,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unRegisterCachingService"
    )
    protected void registerCachingService(CarbonCachingService cachingService, Map<String, ?> properties) {
        CarbonSecurityDataHolder.getInstance().registerCacheService(cachingService);
    }

    protected void unRegisterCachingService(CarbonCachingService carbonCachingService) {
        CarbonSecurityDataHolder.getInstance().registerCacheService(null);
    }

    /**
     * Initialize authentication related configs.
     *
     * @param bundleContext
     */
    private void initAuthenticationConfigs(BundleContext bundleContext) {

        // Initialize proxy login module.
        ProxyLoginModule.init(bundleContext);

        // Set CarbonJAASConfiguration as the implementation of Configuration.
        CarbonJAASConfiguration configuration = new CarbonJAASConfiguration();
        configuration.init();

        // Registering login module provided by the bundle.
        Hashtable<String, String> usernamePasswordLoginModuleProps = new Hashtable<>();
        usernamePasswordLoginModuleProps.put(ProxyLoginModule.LOGIN_MODULE_SEARCH_KEY,
                UsernamePasswordLoginModule.class.getName());
        bundleContext.registerService(LoginModule.class, new UserNamePasswordLoginModuleFactory(),
                usernamePasswordLoginModuleProps);

        // Registering callback handler factories.
        Hashtable<String, String> usernamePasswordCallbackHandlerProps = new Hashtable<>();
        usernamePasswordCallbackHandlerProps.put(CarbonCallbackHandler.SUPPORTED_LOGIN_MODULE,
                CarbonSecurityConstants.USERNAME_PASSWORD_LOGIN_MODULE);
        bundleContext.registerService(CarbonCallbackHandler.class, new UsernamePasswordCallbackHandlerFactory(),
                usernamePasswordCallbackHandlerProps);
    }


    @Override
    public void onAllRequiredCapabilitiesAvailable() {
        log.info("Carbon-Security bundle activated successfully.");
    }
}

