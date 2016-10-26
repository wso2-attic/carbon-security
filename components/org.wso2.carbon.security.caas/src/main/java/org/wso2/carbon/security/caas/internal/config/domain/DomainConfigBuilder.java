package org.wso2.carbon.security.caas.internal.config.domain;

import org.wso2.carbon.security.caas.api.util.CarbonSecurityConstants;
import org.wso2.carbon.security.caas.user.core.exception.ConfigurationFileReadException;
import org.wso2.carbon.security.caas.user.core.util.FileUtil;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Builder for retrieving Domain configurations.
 */
public class DomainConfigBuilder {

    /**
     * Create configuration from the config file.
     *
     * @return DomainConfiguration YAML java representation.
     * @throws ConfigurationFileReadException on error in reading file
     * @throws IOException                    on file not found
     */
    private static DomainConfigFile buildDomainConfig() throws ConfigurationFileReadException, IOException {

        Path file = Paths.get(CarbonSecurityConstants.getCarbonHomeDirectory().toString(), "conf", "security",
                CarbonSecurityConstants.DOMAIN_CONFIG_FILE);

        return FileUtil.readConfigFile(file, DomainConfigFile.class);
    }

    /**
     * Retrieve domain configurations.
     *
     * @return Domain Configuration
     * @throws ConfigurationFileReadException on error in reading file
     * @throws IOException                    on file not found
     */
    public static DomainConfig getDomainConfig()
            throws IOException, ConfigurationFileReadException {

        DomainConfigFile domainConfigFile = buildDomainConfig();

        Map<String, List<DomainIdentityStoreConnectorConfigEntry>> domainIdentityStoreConnectors = new HashMap<>();

        Map<String, Integer> domainToDomainPriority = new HashMap<>();


        domainConfigFile.getDomains().forEach(domainConfigEntry -> {
            String domainName = domainConfigEntry.getDomainName();
            int domainPriority = domainConfigEntry.getDomainPriority();

            List<DomainIdentityStoreConnectorConfigEntry> domainIdentityStoreConnectorConfigEntries =
                    domainConfigEntry.getIdentityStoreConnectors().stream().map(domainStoreConfigEntry -> {

                        Map<String, String> attributeMappings = domainStoreConfigEntry.getAttributeMappings().stream()
                                .flatMap(attributeMapping ->
                                        attributeMapping.entrySet().stream()
                                ).collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

                        return new DomainIdentityStoreConnectorConfigEntry(domainStoreConfigEntry.getConnectorId(),
                                attributeMappings);
                    }).collect(Collectors.toList());

            domainIdentityStoreConnectors.put(domainName, domainIdentityStoreConnectorConfigEntries);

            domainToDomainPriority.put(domainName, domainPriority);

        });

        return new DomainConfig(domainToDomainPriority, domainIdentityStoreConnectors);
    }
}
