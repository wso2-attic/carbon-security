package org.wso2.carbon.security.jaas;

import org.wso2.carbon.jaas.boot.ProxyLoginModule;
import org.wso2.carbon.security.internal.CarbonSecurityDataHolder;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CarbonJAASConfiguration extends Configuration {

    private final sun.security.provider.ConfigFile.Spi spi;

    public CarbonJAASConfiguration() {
        spi = new sun.security.provider.ConfigFile.Spi();
    }

    public void init() {
        Configuration.setConfiguration(this);
    }

    public CarbonJAASConfiguration(URI uri) {
        spi = new sun.security.provider.ConfigFile.Spi(uri);
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
