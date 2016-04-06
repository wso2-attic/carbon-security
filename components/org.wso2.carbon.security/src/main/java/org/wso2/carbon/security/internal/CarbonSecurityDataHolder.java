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

import org.wso2.carbon.security.jaas.HTTPCallbackHandlerFactory;
import org.wso2.carbon.security.usercore.common.CarbonRealmServiceImpl;
import org.wso2.carbon.security.usercore.connector.AuthorizationStoreConnector;
import org.wso2.carbon.security.usercore.connector.CredentialStoreConnector;
import org.wso2.carbon.security.usercore.connector.IdentityStoreConnector;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Carbon security data holder
 */
public class CarbonSecurityDataHolder {

    private static CarbonSecurityDataHolder instance = new CarbonSecurityDataHolder();
    private Map<String, List<HTTPCallbackHandlerFactory>> callbackHandlerFactoryMap;
    private Map<String, Long> loginModuleMap;
    private CarbonRealmServiceImpl carbonRealmService;
    private Map<String, AuthorizationStoreConnector> authorizationStoreConnectorMap = new HashMap<>();
    private Map<String, CredentialStoreConnector> credentialStoreConnectorMap = new HashMap<>();
    private Map<String, IdentityStoreConnector> identityStoreConnectorMap = new HashMap<>();

    private CarbonSecurityDataHolder() {

        this.callbackHandlerFactoryMap = new HashMap<>();
        this.loginModuleMap = new HashMap<>();
    }

    public static CarbonSecurityDataHolder getInstance() {
        return instance;
    }

    public void registerCallbackHandlerFactory(HTTPCallbackHandlerFactory callbackHandlerFactory) {

        if (callbackHandlerFactoryMap.get(callbackHandlerFactory.getSupportedLoginModuleType()) == null) {
            synchronized (callbackHandlerFactoryMap) {
                if (callbackHandlerFactoryMap.get(callbackHandlerFactory.getSupportedLoginModuleType()) == null) {
                    callbackHandlerFactoryMap.put(callbackHandlerFactory.getSupportedLoginModuleType(),
                                                  Arrays.asList(callbackHandlerFactory));
                }
            }
        } else {
            synchronized (callbackHandlerFactoryMap) {
                callbackHandlerFactoryMap.get(callbackHandlerFactory.getSupportedLoginModuleType()).add
                        (callbackHandlerFactory);
            }
        }
    }

    public void unregisterCallbackHandlerFactory(HTTPCallbackHandlerFactory callbackHandlerFactory) {

        synchronized (callbackHandlerFactoryMap) {
            callbackHandlerFactoryMap.get(callbackHandlerFactory.getSupportedLoginModuleType()).remove
                    (callbackHandlerFactory);
        }
    }

    public List<HTTPCallbackHandlerFactory> getCallbackHandlerFactory(String type) {

        return callbackHandlerFactoryMap.get(type);
    }

    public void registerCarbonRealmService(CarbonRealmServiceImpl carbonRealmService) {

        this.carbonRealmService = carbonRealmService;
    }

    public CarbonRealmServiceImpl getCarbonRealmService() {

        return this.carbonRealmService;
    }

    public void addLoginModule(long bundleId, String className) {

        loginModuleMap.put(className, bundleId);
    }

    public void removeLoginModule(long bundleId, String className) {

        loginModuleMap.remove(className, bundleId);
    }

    public Long getBundleIdOfLoginModule(String className) {

        return loginModuleMap.get(className);
    }

    public void registerAuthorizationStoreConnector(String key, AuthorizationStoreConnector authorizationStoreConnector)
    {
        authorizationStoreConnectorMap.put(key, authorizationStoreConnector);
    }

    public void registerCredentialStoreConnector(String key, CredentialStoreConnector credentialStoreConnector) {
        credentialStoreConnectorMap.put(key, credentialStoreConnector);
    }

    public void registerIdentityStoreConnector(String key, IdentityStoreConnector identityStoreConnector) {
        identityStoreConnectorMap.put(key, identityStoreConnector);
    }

    public Map<String, AuthorizationStoreConnector> getAuthorizationStoreConnectorMap() {
        return authorizationStoreConnectorMap;
    }

    public Map<String, CredentialStoreConnector> getCredentialStoreConnectorMap() {
        return credentialStoreConnectorMap;
    }

    public Map<String, IdentityStoreConnector> getIdentityStoreConnectorMap() {
        return identityStoreConnectorMap;
    }
}
