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

package org.wso2.carbon.security.internal;

import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.service.jndi.JNDIContextManager;
import org.osgi.service.permissionadmin.PermissionAdmin;
import org.osgi.service.permissionadmin.PermissionInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.security.internal.config.DefaultPermissionInfo;
import org.wso2.carbon.security.internal.config.DefaultPermissionInfoCollection;
import org.wso2.carbon.security.internal.config.SecurityConfigBuilder;
import org.wso2.carbon.security.jaas.CarbonCallbackHandlerFactory;
import org.wso2.carbon.security.jaas.CarbonPolicy;
import org.wso2.carbon.security.jaas.HTTPCallbackHandler;
import org.wso2.carbon.security.jaas.handler.BasicAuthCallbackHandler;
import org.wso2.carbon.security.jaas.handler.BasicAuthCallbackHandlerFactory;
import org.wso2.carbon.security.jaas.handler.JWTCallbackHandler;
import org.wso2.carbon.security.jaas.handler.JWTCallbackHandlerFactory;
import org.wso2.carbon.security.jaas.handler.SAMLCallbackHandler;
import org.wso2.carbon.security.jaas.handler.SAMLCallbackHandlerFactory;
import org.wso2.carbon.security.usercore.common.CarbonRealmServiceImpl;
import org.wso2.carbon.security.usercore.service.RealmService;
import org.wso2.carbon.security.usercore.util.DatabaseUtil;

import javax.naming.Context;
import javax.naming.NamingException;
import java.security.Policy;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * OSGi service component which handle authentication and authorization
 */
@Component(
        name = "org.wso2.carbon.security.internal.CarbonSecurityComponent",
        immediate = true
)
public class CarbonSecurityComponent {

    private static final Logger log = LoggerFactory.getLogger(CarbonSecurityComponent.class);
    private ServiceRegistration registration;

    @Activate
    public void registerCarbonSecurityProvider(BundleContext bundleContext) {

        // Set default permissions if security manager is enabled
        if(System.getProperty("java.security.manager") != null) {
            // Set default permissions for all bundles
            setDefaultPermissions(bundleContext);

            // Registering CarbonPolicy
            CarbonPolicy policy = new CarbonPolicy();
            Policy.setPolicy(policy);
        }

        // Set default callback handlers
        CarbonSecurityDataHolder.getInstance().registerCallbackHandlerFactory(new BasicAuthCallbackHandlerFactory());
        CarbonSecurityDataHolder.getInstance().registerCallbackHandlerFactory(new JWTCallbackHandlerFactory());
        CarbonSecurityDataHolder.getInstance().registerCallbackHandlerFactory(new SAMLCallbackHandlerFactory());

        try {
            // Set JNDI context for the later use.
            this.setJNDIContext(bundleContext);
        } catch (NamingException e) {
            log.error("Error while setting the JNDI context.", e);
        }

        try {
            registration = bundleContext.registerService(RealmService.class.getName(), new CarbonRealmServiceImpl(),
                                                         null);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }

        log.info("Carbon-Security bundle activated successfully.");
    }

    @Deactivate
    public void unregisterCarbonSecurityProvider(BundleContext bundleContext) {

        try {
            bundleContext.ungetService(registration.getReference());
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        log.info("Carbon-Security bundle deactivated successfully.");
    }

    @Reference(
            name = "httpCallbackHandlerFactories",
            service = CarbonCallbackHandlerFactory.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unregisterCallbackHandlerFactory"
    )
    protected void registerCallbackHandlerFactory(CarbonCallbackHandlerFactory callbackHandlerFactory, Map<String, ?> ref) {
        CarbonSecurityDataHolder.getInstance().registerCallbackHandlerFactory(callbackHandlerFactory);
    }

    protected void unregisterCallbackHandlerFactory(CarbonCallbackHandlerFactory callbackHandlerFactory, Map<String, ?> ref) {
        CarbonSecurityDataHolder.getInstance().unregisterCallbackHandlerFactory(callbackHandlerFactory);
    }

    /**
     * Set default permissions for all bundles using PermissionAdmin
     *
     * @param context
     */
    private void setDefaultPermissions(BundleContext context) {

        PermissionAdmin permissionAdmin = getPermissionAdmin(context);
        if (permissionAdmin != null) {

            DefaultPermissionInfoCollection permissionInfoCollection = SecurityConfigBuilder
                    .buildDefaultPermissionInfoCollection();
            List<PermissionInfo> permissionInfoList = new ArrayList<>();
            if (!Collections.EMPTY_SET.equals(permissionInfoCollection.getPermissions())) {

                for (DefaultPermissionInfo permissionInfo : permissionInfoCollection.getPermissions()) {

                    if (permissionInfo.getType() == null || permissionInfo.getType().trim().isEmpty()) {
                        throw new IllegalArgumentException("type can't be null or empty");

                    }

                    if (permissionInfo.getName() == null || permissionInfo.getName().trim().isEmpty()) {
                        throw new IllegalArgumentException("name can't be null or empty");
                    }

                    permissionInfoList.add(new PermissionInfo(permissionInfo.getType(), permissionInfo.getName(),
                                                              (permissionInfo.getActions() != null && !permissionInfo
                                                                      .getActions().trim().isEmpty()) ?
                                                              permissionInfo.getActions().trim() : null));
                }
            } else {
                throw new RuntimeException("Default permission info collection can't be empty");
            }

            permissionAdmin.setDefaultPermissions(permissionInfoList
                                                          .toArray(new PermissionInfo[permissionInfoList.size()]));
        }
    }

    private PermissionAdmin getPermissionAdmin(BundleContext context) {
        return (PermissionAdmin) context.getService(context.getServiceReference(PermissionAdmin.class.getName()));
    }

    private void setJNDIContext(BundleContext bundleContext) throws NamingException {

        ServiceReference<JNDIContextManager> contextManagerSRef = bundleContext.getServiceReference(
                JNDIContextManager.class);

        JNDIContextManager jndiContextManager = Optional.ofNullable(contextManagerSRef)
                .map(bundleContext::getService)
                .orElseThrow(() -> new RuntimeException("JNDIContextManager service is not available."));

        Context initialContext = jndiContextManager.newInitialContext();
        DatabaseUtil.getInstance().setJNDIContext(initialContext);
    }
}

