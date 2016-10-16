package org.wso2.carbon.security.caas.internal.config.domain;

import org.wso2.carbon.security.caas.api.util.CarbonSecurityConstants;
import org.wso2.carbon.security.caas.user.core.exception.DomainConfigException;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.introspector.BeanAccess;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
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
     */
    private static DomainConfigFile buildDomainConfig() throws DomainConfigException {

        Path file = Paths.get(CarbonSecurityConstants.getCarbonHomeDirectory().toString(), "conf", "security",
                CarbonSecurityConstants.DOMAIN_CONFIG_FILE);

        DomainConfigFile domainConfigFile;
        if (Files.exists(file)) {
            try (Reader in = new InputStreamReader(Files.newInputStream(file), StandardCharsets.UTF_8)) {
                Yaml yaml = new Yaml();
                yaml.setBeanAccess(BeanAccess.FIELD);
                domainConfigFile = yaml.loadAs(in, DomainConfigFile.class);
            } catch (IOException e) {
                throw new DomainConfigException("Error while loading " + CarbonSecurityConstants.DOMAIN_CONFIG_FILE +
                        " configuration file", e);
            }
        } else {
            throw new DomainConfigException("Configuration file " + CarbonSecurityConstants.DOMAIN_CONFIG_FILE
                    + "' is not available.");
        }
        return domainConfigFile;
    }

    /**
     * Retrieve domain configurations.
     *
     * @return Domain Configuration
     * @throws DomainConfigException DomainConfigException
     */
    public static DomainConfig getDomainConfig()
            throws DomainConfigException {

        DomainConfigFile domainConfigFile = buildDomainConfig();

        Map<String, List<DomainIdentityStoreConnectorConfigEntry>> domainIdentityStoreConnectors = new HashMap<>();

        Map<String, Integer> domainToDomainPriority = new HashMap<>();


        domainConfigFile.getDomains().stream().forEach(domainConfigEntry -> {
            String domainName = domainConfigEntry.getDomainName();
            int domainPriority = domainConfigEntry.getDomainPriority();

            List<DomainIdentityStoreConnectorConfigEntry> domainIdentityStoreConnectorConfigEntries =
                    domainConfigEntry.getIdentityStoreConnectors().stream().map(domainStoreConfigEntry -> {

                Map<String, String> attributeMappings = domainStoreConfigEntry.getAttributeMappings().stream()
                        .flatMap(attributeMapping ->
                                        attributeMapping.entrySet().stream()
                        ).collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

                return new DomainIdentityStoreConnectorConfigEntry(domainStoreConfigEntry.getConnectorName(),
                        attributeMappings);
            }).collect(Collectors.toList());

            domainIdentityStoreConnectors.put(domainName, domainIdentityStoreConnectorConfigEntries);

            domainToDomainPriority.put(domainName, domainPriority);

        });

        return new DomainConfig(domainToDomainPriority, domainIdentityStoreConnectors);
    }
}
