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
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.service.permissionadmin.PermissionAdmin;
import org.osgi.service.permissionadmin.PermissionInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.security.boot.ProxyLoginModule;
import org.wso2.carbon.security.internal.config.DefaultPermissionInfo;
import org.wso2.carbon.security.internal.config.DefaultPermissionInfoCollection;
import org.wso2.carbon.security.internal.config.SecurityConfigBuilder;
import org.wso2.carbon.security.internal.osgi.JWTLoginModuleFactory;
import org.wso2.carbon.security.internal.osgi.SAML2LoginModuleFactory;
import org.wso2.carbon.security.internal.osgi.UserNamePasswordLoginModuleFactory;
import org.wso2.carbon.security.jaas.CarbonJAASConfiguration;
import org.wso2.carbon.security.jaas.CarbonPolicy;
import org.wso2.carbon.security.jaas.HTTPCallbackHandlerFactory;
import org.wso2.carbon.security.jaas.handler.BasicAuthCallbackHandlerFactory;
import org.wso2.carbon.security.jaas.handler.JWTCallbackHandlerFactory;
import org.wso2.carbon.security.jaas.handler.SAMLCallbackHandlerFactory;
import org.wso2.carbon.security.jaas.modules.JWTLoginModule;
import org.wso2.carbon.security.jaas.modules.SAML2LoginModule;
import org.wso2.carbon.security.jaas.modules.UsernamePasswordLoginModule;
import org.wso2.carbon.security.usercore.common.CarbonRealmServiceImpl;
import org.wso2.carbon.security.usercore.connector.AuthorizationStoreConnector;
import org.wso2.carbon.security.usercore.connector.CredentialStoreConnector;
import org.wso2.carbon.security.usercore.connector.IdentityStoreConnector;
import org.wso2.carbon.security.usercore.service.RealmService;

import javax.security.auth.spi.LoginModule;
import java.security.Policy;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;

/**
 * OSGi service component which handle authentication and authorization.
 */
@Component(
        name = "org.wso2.carbon.security.internal.CarbonSecurityComponent",
        immediate = true
)
public class CarbonSecurityComponent {

    private static final Logger log = LoggerFactory.getLogger(CarbonSecurityComponent.class);

    private ServiceRegistration realmServiceRegistration;

    private ServiceRegistration loginModuleServiceRegistration;

    @Activate
    public void registerCarbonSecurityProvider(BundleContext bundleContext) {

        initAuthenticationConfigs(bundleContext);

        // if security manager is enabled init authorization configs
        if (System.getProperty("java.security.manager") != null) {
            initAuthorizationConfigs(bundleContext);
        }

        try {
            CarbonRealmServiceImpl carbonRealmService = new CarbonRealmServiceImpl();
            CarbonSecurityDataHolder.getInstance().registerCarbonRealmService(carbonRealmService);
            realmServiceRegistration = bundleContext.registerService(RealmService.class.getName(),
                                                                     carbonRealmService, null);
        } catch (Throwable e) {
            log.error(e.getMessage(), e);
        }

        log.info("Carbon-Security bundle activated successfully.");
    }

    @Deactivate
    public void unregisterCarbonSecurityProvider(BundleContext bundleContext) {

        try {
            bundleContext.ungetService(realmServiceRegistration.getReference());
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }

        try {
            bundleContext.ungetService(loginModuleServiceRegistration.getReference());
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }

        log.info("Carbon-Security bundle deactivated successfully.");
    }

    @Reference(
            name = "httpCallbackHandlerFactories",
            service = HTTPCallbackHandlerFactory.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unregisterCallbackHandlerFactory"
    )
    protected void registerCallbackHandlerFactory(HTTPCallbackHandlerFactory callbackHandlerFactory,
                                                  Map<String, ?> ref) {
        CarbonSecurityDataHolder.getInstance().registerCallbackHandlerFactory(callbackHandlerFactory);
    }

    protected void unregisterCallbackHandlerFactory(HTTPCallbackHandlerFactory callbackHandlerFactory,
                                                    Map<String, ?> ref) {
        CarbonSecurityDataHolder.getInstance().unregisterCallbackHandlerFactory(callbackHandlerFactory);
    }

    @Reference(
            name = "org.wso2.carbon.security.usercore.connector.AuthorizationStoreConnector",
            service = AuthorizationStoreConnector.class,
            cardinality = ReferenceCardinality.AT_LEAST_ONE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unregisterAuthorizationStoreConnector"
    )
    protected void registerAuthorizationConnector(AuthorizationStoreConnector authorizationStoreConnector,
                                                  Map<String, String> properties) {

        String connectorId = properties.get("connector-id");
        CarbonSecurityDataHolder.getInstance().registerAuthorizationStoreConnector(connectorId,
                authorizationStoreConnector);
    }

    protected void unregisterAuthorizationStoreConnector(AuthorizationStoreConnector authorizationStoreConnector) {
    }

    @Reference(
            name = "org.wso2.carbon.security.usercore.connector.IdentityStoreConnector",
            service = IdentityStoreConnector.class,
            cardinality = ReferenceCardinality.AT_LEAST_ONE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unregisterIdentityStoreConnector"
    )
    protected void registerIdentityConnector(IdentityStoreConnector identityStoreConnector,
                                             Map<String, String> properties) {

        String connectorId = properties.get("connector-id");
        CarbonSecurityDataHolder.getInstance().registerIdentityStoreConnector(connectorId,
                identityStoreConnector);
    }

    protected void unregisterIdentityStoreConnector(IdentityStoreConnector identityStoreConnector) {
    }

    @Reference(
            name = "org.wso2.carbon.security.usercore.connector.CredentialStoreConnector",
            service = CredentialStoreConnector.class,
            cardinality = ReferenceCardinality.AT_LEAST_ONE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unregisterCredentialStoreConnector"
    )
    protected void registerCredentialConnector(CredentialStoreConnector credentialStoreConnector,
                                               Map<String, String> properties) {

        String connectorId = properties.get("connector-id");
        CarbonSecurityDataHolder.getInstance().registerCredentialStoreConnector(connectorId,
                credentialStoreConnector);
    }

    protected void unregisterCredentialStoreConnector(CredentialStoreConnector credentialStoreConnector) {
    }


    private void initAuthenticationConfigs(BundleContext bundleContext) {

        // Initialize proxy login module
        ProxyLoginModule.init(bundleContext);

        // Set CarbonJAASConfiguration as the implantation of Configuration
        CarbonJAASConfiguration configuration = new CarbonJAASConfiguration();
        configuration.init();

        //Registering login modules provided by the bundle
        Hashtable<String, String> paramDictionary1 = new Hashtable<>();
        paramDictionary1.put("login.module.class.name", UsernamePasswordLoginModule.class.getName());
        bundleContext.registerService(LoginModule.class, new UserNamePasswordLoginModuleFactory(), paramDictionary1);

        Hashtable<String, String> paramDictionary2 = new Hashtable<>();
        paramDictionary2.put("login.module.class.name", JWTLoginModule.class.getName());
        bundleContext.registerService(LoginModule.class, new JWTLoginModuleFactory(), paramDictionary2);

        Hashtable<String, String> paramDictionary3 = new Hashtable<>();
        paramDictionary3.put("login.module.class.name", SAML2LoginModule.class.getName());
        bundleContext.registerService(LoginModule.class, new SAML2LoginModuleFactory(), paramDictionary3);

        // Registering callback handler factories
        CarbonSecurityDataHolder.getInstance().registerCallbackHandlerFactory(new BasicAuthCallbackHandlerFactory());
        CarbonSecurityDataHolder.getInstance().registerCallbackHandlerFactory(new JWTCallbackHandlerFactory());
        CarbonSecurityDataHolder.getInstance().registerCallbackHandlerFactory(new SAMLCallbackHandlerFactory());
    }

    private void initAuthorizationConfigs(BundleContext bundleContext) {

        // Set default permissions for all bundles
        setDefaultPermissions(bundleContext);

        // Registering CarbonPolicy
        CarbonPolicy policy = new CarbonPolicy();
        Policy.setPolicy(policy);
    }

    /**
     * Set default permissions for all bundles using PermissionAdmin.
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
}

