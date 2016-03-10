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
