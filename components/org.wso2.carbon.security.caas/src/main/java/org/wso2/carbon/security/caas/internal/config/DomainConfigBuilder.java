package org.wso2.carbon.security.caas.internal.config;

import org.wso2.carbon.security.caas.api.util.CarbonSecurityConstants;
import org.wso2.carbon.security.caas.user.core.claim.MetaClaim;
import org.wso2.carbon.security.caas.user.core.claim.MetaClaimMapping;
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
import java.util.ArrayList;
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
    private static DomainConfigFile buildDomainConfig() {

        Path file = Paths.get(CarbonSecurityConstants.getCarbonHomeDirectory().toString(), "conf", "security",
                CarbonSecurityConstants.DOMAIN_CONFIG_FILE);

        DomainConfigFile domainConfigFile;
        if (Files.exists(file)) {
            try (Reader in = new InputStreamReader(Files.newInputStream(file), StandardCharsets.UTF_8)) {
                Yaml yaml = new Yaml();
                yaml.setBeanAccess(BeanAccess.FIELD);
                domainConfigFile = new Yaml().loadAs(in, DomainConfigFile.class);
            } catch (IOException e) {
                throw new RuntimeException("Error while loading " + CarbonSecurityConstants.DOMAIN_CONFIG_FILE +
                        " configuration file", e);
            }
        } else {
            throw new RuntimeException("Configuration file " + CarbonSecurityConstants.DOMAIN_CONFIG_FILE + "' is not" +
                    " available.");
        }
        return domainConfigFile;
    }

    /**
     * Retrieve domain configurations.
     *
     * @param metaClaims MetaClaims that are referenced from domain configuration, <ClaimURI, MetaClaim>.
     * @return Domain Configuration
     * @throws DomainConfigException DomainConfigException
     */
    public static DomainConfig getDomainConfig(Map<String, MetaClaim> metaClaims)
            throws DomainConfigException {

        DomainConfigFile domainConfigFile = buildDomainConfig();

        Map<String, List<String>> domainIdentityStoreConnectors = new HashMap<>();
        Map<String, List<String>> domainCredentialStoreConnectors = new HashMap<>();

        Map<String, List<MetaClaimMapping>> identityStoreConnectorMapping = new HashMap<>();

        Map<Integer, List<String>> domainPriorityToDomainMap = new HashMap<>();

        for (DomainConfigEntry domainConfigEntry : domainConfigFile.getDomainConfigEntries()) {
            // Set domain name
            String domainName = domainConfigEntry.getDomainName();
            int domainPriority = domainConfigEntry.getDomainPriority();

            List<String> identityStoreConnectors = new ArrayList<>();
            List<String> credentialStoreConnectors = new ArrayList<>();

            for (DomainStoreConfigEntry identityStoreConfigEntry : domainConfigEntry.getIdentityStoreConnectors()) {
                // Add domain to connector mapping
                String identityStoreConnectorId = identityStoreConfigEntry.getStoreConnectorId();
                identityStoreConnectors.add(identityStoreConnectorId);

                List<MetaClaimMapping> metaClaimMappings = new ArrayList<>();

                for (DomainAttributeConfigEntry domainAttributeConfigEntry : identityStoreConfigEntry
                        .getAttributeMappings()) {
                    MetaClaim metaClaim = metaClaims.get(domainAttributeConfigEntry.getClaimURI());
                    MetaClaimMapping metaClaimMapping = new MetaClaimMapping(metaClaim, identityStoreConnectorId,
                            domainAttributeConfigEntry.getAttribute());

                    metaClaimMappings.add(metaClaimMapping);
                }

                identityStoreConnectorMapping.put(identityStoreConnectorId, metaClaimMappings);
            }

            // Check for duplicate domain names
            // It is not necessary to check other maps since the same domain name is added
            if (domainIdentityStoreConnectors.containsKey(domainName)) {
                throw new DomainConfigException(String
                        .format("Duplicate domain name entries detected in domain configuration for domain name %s",
                                domainName));
            }

            domainIdentityStoreConnectors.put(domainName, identityStoreConnectors);

            // Add domain to connector mapping
            credentialStoreConnectors.addAll(domainConfigEntry.getIdentityStoreConnectors().stream().map
                    (DomainStoreConfigEntry::getStoreConnectorId).collect(Collectors.toList()));

            domainCredentialStoreConnectors.put(domainName, credentialStoreConnectors);

            // Add domain to domain priority list
            if (!domainPriorityToDomainMap.containsKey(domainPriority)) {
                domainPriorityToDomainMap.put(domainPriority, new ArrayList<>());
            }

            domainPriorityToDomainMap.get(domainPriority).add(domainName);
        }


        return new DomainConfig(domainPriorityToDomainMap, domainIdentityStoreConnectors,
                domainCredentialStoreConnectors, identityStoreConnectorMapping);
    }
}
