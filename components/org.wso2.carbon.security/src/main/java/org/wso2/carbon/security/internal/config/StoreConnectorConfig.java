package org.wso2.carbon.security.internal.config;

import java.util.Properties;

/**
 * StoreConnectorConfig Bean
 *
 * @since 1.0.0
 */
public class StoreConnectorConfig {

    private String name;

    private Properties properties;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Properties getProperties() {
        return properties;
    }

    public void setProperties(Properties properties) {
        this.properties = properties;
    }
}

