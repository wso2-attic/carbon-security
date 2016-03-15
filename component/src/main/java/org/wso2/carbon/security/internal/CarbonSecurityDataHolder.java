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

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CarbonSecurityDataHolder {

    private static CarbonSecurityDataHolder instance = new CarbonSecurityDataHolder();

    private static Map<String, List<HTTPCallbackHandlerFactory>> callbackHandlerFactoryMap;
    private static CarbonRealmServiceImpl carbonRealmService;

    private CarbonSecurityDataHolder() {
        this.callbackHandlerFactoryMap = new HashMap<>();
    }

    public static CarbonSecurityDataHolder getInstance() {
        return instance;
    }

    public void registerCallbackHandlerFactory(HTTPCallbackHandlerFactory callbackHandlerFactory) {
        if (callbackHandlerFactoryMap.get(callbackHandlerFactory.getSupportedLoginModuleType()) == null) {
            synchronized (callbackHandlerFactoryMap) {
                if (callbackHandlerFactoryMap.get(callbackHandlerFactory.getSupportedLoginModuleType()) == null) {
                    callbackHandlerFactoryMap.put(callbackHandlerFactory.getSupportedLoginModuleType(), Arrays.asList(callbackHandlerFactory));
                }
            }
        } else {
            synchronized (callbackHandlerFactoryMap) {
                callbackHandlerFactoryMap.get(callbackHandlerFactory.getSupportedLoginModuleType()).add(callbackHandlerFactory);
            }
        }
    }

    public void unregisterCallbackHandlerFactory(HTTPCallbackHandlerFactory callbackHandlerFactory) {
        synchronized (callbackHandlerFactoryMap) {
            callbackHandlerFactoryMap.get(callbackHandlerFactory.getSupportedLoginModuleType()).remove(callbackHandlerFactory);
        }
    }

    public List<HTTPCallbackHandlerFactory> getCallbackHandlerFactory(String type) {
        return callbackHandlerFactoryMap.get(type);
    }

    public void registerCarbonRealmService(CarbonRealmServiceImpl carbonRealmService) {
        CarbonSecurityDataHolder.carbonRealmService = carbonRealmService;
    }

    public CarbonRealmServiceImpl getCarbonRealmService() {
        return CarbonSecurityDataHolder.carbonRealmService;
    }
}
