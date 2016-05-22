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

package org.wso2.carbon.security.caas.api;

import org.wso2.carbon.security.caas.boot.ProxyLoginModule;
import sun.security.provider.ConfigFile.Spi;

import java.net.URI;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;

/**
 * This contains the carbon implementation of the Configuration class.
 *
 * @since 1.0.0
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

        return Arrays.asList(configurationEntries)
                .stream()
                .map(this::createProxyEntry)
                .collect(Collectors.toList())
                .toArray(new AppConfigurationEntry[configurationEntries.length]);
    }

    private AppConfigurationEntry createProxyEntry(AppConfigurationEntry entry) {
        Map<String, Object> options = new HashMap<>(entry.getOptions());
        options.put(ProxyLoginModule.LOGIN_MODULE_OPTION_KEY, entry.getLoginModuleName());
        return new AppConfigurationEntry(ProxyLoginModule.class.getName(), entry.getControlFlag(), options);
    }

    @Override
    public void refresh() {
        spi.engineRefresh();
    }
}
