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

package org.wso2.carbon.security.caas.internal.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.security.caas.api.util.CarbonSecurityConstants;
import org.wso2.carbon.security.caas.user.core.claim.MetaClaim;
import org.wso2.carbon.security.caas.user.core.claim.MetaClaimMapping;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.introspector.BeanAccess;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Collectors;

/**
 * Claim Config Builder.
 */
public class ClaimConfigBuilder {

    private static final Logger log = LoggerFactory.getLogger(ClaimConfigBuilder.class);

    public static ClaimConfig getClaimConfig() {

        ClaimConfigFile claimConfigFile = buildClaimConfigs();
        if (claimConfigFile.getClaimManager() == null || claimConfigFile.getClaimManager().trim().isEmpty()) {
            throw new RuntimeException("Value for 'claimManager' must present in the claim-config.xml ");
        }

        ClaimConfig claimConfig = new ClaimConfig();
        claimConfig.setClaimManager(claimConfigFile.getClaimManager().trim());

        if (claimConfigFile.getClaims() != null) {

            claimConfig.setClaimMappings(claimConfigFile.getClaims().stream()
                    // Claim URI must be present
                    .filter(claimEntry -> claimEntry.getClaimURI() != null &&
                            !claimEntry.getClaimURI().trim().isEmpty())
                    // Get MetaClaimMapping from a ClaimEntry
                    .map(claimEntry -> {
                        MetaClaim metaClaim = new MetaClaim();
                        metaClaim.setDialectURI(claimConfigFile.getDialectURI().trim());
                        metaClaim.setClaimURI(claimEntry.getClaimURI().trim());
                        if (claimEntry.getProperties() != null) {
                            metaClaim.setProperties(claimEntry.getProperties().entrySet()
                                    .stream()
                                    .collect(Collectors.toMap(
                                            prop -> (String) prop.getKey(),
                                            prop -> (String) prop.getValue()
                                    )));
                        }

                        MetaClaimMapping metaClaimMapping = new MetaClaimMapping();
                        metaClaimMapping.setMetaClaim(metaClaim);
                        if (claimEntry.getMappedAttributes() != null) {
                            metaClaimMapping.setAttributeNamesMap(claimEntry.getMappedAttributes().entrySet()
                                    .stream()
                                    .collect(Collectors.toMap(
                                            prop -> (String) prop.getKey(),
                                            prop -> (String) prop.getValue()
                                    )));
                        }

                        return metaClaimMapping;
                    })
                    // At least one mapped attribute must be present
                    .filter(claimMapping -> claimMapping.getAttributeNamesMap().size() > 0)
                    .collect(Collectors.toMap(claimMapping -> claimMapping.getMetaClaim().getClaimURI(),
                            claimMapping -> claimMapping)));
        }
        return claimConfig;
    }

    private static ClaimConfigFile buildClaimConfigs() {

        Path file = Paths.get(CarbonSecurityConstants.getCarbonHomeDirectory().toString(), "conf", "security",
                CarbonSecurityConstants.CLAIM_CONFIG_FILE);

        ClaimConfigFile claimConfigFile;
        if (Files.exists(file)) {
            try (Reader in = new InputStreamReader(Files.newInputStream(file), StandardCharsets.ISO_8859_1)) {
                Yaml yaml = new Yaml();
                yaml.setBeanAccess(BeanAccess.FIELD);
                claimConfigFile = new Yaml().loadAs(in, ClaimConfigFile.class);
            } catch (IOException e) {
                throw new RuntimeException("Error while loading " + CarbonSecurityConstants.CLAIM_CONFIG_FILE +
                        " configuration file", e);
            }
        } else {
            throw new RuntimeException("Configuration file " + CarbonSecurityConstants.CLAIM_CONFIG_FILE + "' is not" +
                    " available.");
        }
        return claimConfigFile;
    }

}
