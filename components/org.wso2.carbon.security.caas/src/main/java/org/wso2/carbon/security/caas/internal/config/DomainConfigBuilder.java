package org.wso2.carbon.security.caas.internal.config;

import org.wso2.carbon.security.caas.api.util.CarbonSecurityConstants;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.introspector.BeanAccess;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Builder for retrieving Domain configurations.
 */
public class DomainConfigBuilder {

    private static DomainConfigFile buildDomainConfig() {

//        Path file = Paths.get(CarbonSecurityConstants.getCarbonHomeDirectory().toString(), "conf", "security",
//                CarbonSecurityConstants.DOMAIN_CONFIG_FILE);
        Path file = Paths.get("/Users/Akalanka/git/carbon-security/feature/resources/conf/domain-config.yml");

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

    public static void main(String []args) {
        DomainConfigFile d = buildDomainConfig();

        System.out.println(d.getDomains().get(0).domainName);

        System.out.println("done");
    }
}
