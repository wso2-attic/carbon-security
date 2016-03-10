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

import org.wso2.carbon.security.jaas.HTTPCallbackHandler;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CarbonSecurityDataHolder {

    private static CarbonSecurityDataHolder instance = new CarbonSecurityDataHolder();

    private static Map<String, List<HTTPCallbackHandler>> httpCallbackHandlerMap;

    private CarbonSecurityDataHolder() {
        this.httpCallbackHandlerMap = new HashMap<>();
    }

    public static CarbonSecurityDataHolder getInstance() {
        return instance;
    }

    public void addCallbackHandler(HTTPCallbackHandler httpCallbackHandler) {
        if (httpCallbackHandlerMap.get(httpCallbackHandler.getSupportedLoginModuleType()) == null) {
            synchronized (httpCallbackHandlerMap) {
                if (httpCallbackHandlerMap.get(httpCallbackHandler.getSupportedLoginModuleType()) == null) {
                    httpCallbackHandlerMap.put(httpCallbackHandler.getSupportedLoginModuleType(), Arrays.asList(httpCallbackHandler));
                }
            }
        } else {
            synchronized (httpCallbackHandlerMap) {
                httpCallbackHandlerMap.get(httpCallbackHandler.getSupportedLoginModuleType()).add(httpCallbackHandler);
            }
        }
    }

    public void removeCallbackHandler(HTTPCallbackHandler httpCallbackHandler) {
        synchronized (httpCallbackHandlerMap) {
            httpCallbackHandlerMap.get(httpCallbackHandler.getSupportedLoginModuleType()).remove(httpCallbackHandler);
        }
    }

    public List<HTTPCallbackHandler> getCallbackHandler(String type) {
        return httpCallbackHandlerMap.get(type);
    }

}
