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

package org.wso2.carbon.security.jaas;

import org.wso2.carbon.security.boot.ProxyLoginModule;
import org.wso2.carbon.security.internal.CarbonSecurityDataHolder;
import sun.security.provider.ConfigFile.Spi;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This contains the carbon implementation of the Configuration class
 */
public class CarbonJAASConfiguration extends Configuration {

    private final Spi spi;

    public CarbonJAASConfiguration() {
        spi = new Spi();
    }

    public void init() {
        Configuration.setConfiguration(this);
    }

    public CarbonJAASConfiguration(URI uri) {
        spi = new Spi(uri);
    }

    @Override
    public AppConfigurationEntry[] getAppConfigurationEntry(String applicationName) {

        AppConfigurationEntry[] configurationEntries = spi.engineGetAppConfigurationEntry(applicationName);

        if (configurationEntries == null) {
            return configurationEntries;
        }

        List<AppConfigurationEntry> updatedConfigurationEntries = new ArrayList<>();

        for (AppConfigurationEntry appConfigurationEntry : configurationEntries) {

            Long bundleId = CarbonSecurityDataHolder.getInstance().getBundleIdOfLoginModule
                    (appConfigurationEntry.getLoginModuleName());
            if (bundleId == null) {
                throw new IllegalStateException("Login module " + appConfigurationEntry.getLoginModuleName()
                                                + " must be registered using LoginModuleService.");
            }

            Map options = new HashMap<>(appConfigurationEntry.getOptions());
            options.put(ProxyLoginModule.PROPERTY_LOGIN_MODULE, appConfigurationEntry.getLoginModuleName());
            options.put(ProxyLoginModule.PROPERTY_BUNDLE_ID, String.valueOf(bundleId));

            updatedConfigurationEntries.add(new AppConfigurationEntry(ProxyLoginModule.class.getName(),
                                                                      appConfigurationEntry.getControlFlag(),
                                                                      Collections.unmodifiableMap(options)));

        }

        return updatedConfigurationEntries.toArray(new AppConfigurationEntry[updatedConfigurationEntries.size()]);
    }

    @Override
    public void refresh() {
        spi.engineRefresh();
    }
}
