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

package org.wso2.carbon.security.caas.user.core.claim;

import org.wso2.carbon.security.caas.api.util.CarbonSecurityConstants;
import org.wso2.carbon.security.caas.user.core.exception.CarbonSecurityConfigException;
import org.wso2.carbon.security.caas.user.core.exception.MetaClaimStoreException;
import org.wso2.carbon.security.caas.user.core.util.FileUtil;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * File based implementation for {@link MetaClaimStore}.
 */
public class FileBasedMetaClaimStore implements MetaClaimStore {

    /**
     * ClaimURI to MetaClaim map.
     */
    Map<String, MetaClaim> metaClaims;

    /**
     * Initialize meta claim store by eagerly loading meta claims from file.
     *
     * @throws CarbonSecurityConfigException
     */
    public FileBasedMetaClaimStore() throws CarbonSecurityConfigException {

        Path file = Paths.get(CarbonSecurityConstants.getCarbonHomeDirectory().toString(), "conf", "security",
                CarbonSecurityConstants.CLAIM_STORE_FILE);

        MetaClaimStoreFile metaClaimStoreFile = FileUtil.readConfigFile(file, MetaClaimStoreFile.class);

        metaClaims = metaClaimStoreFile.getClaims().stream()
                .collect(Collectors.toMap(MetaClaim::getClaimURI, metaClaim -> metaClaim));
    }

    @Override
    public MetaClaim getMetaClaim(String claimURI) throws MetaClaimStoreException {
        MetaClaim metaClaim = metaClaims.get(claimURI);

        if (metaClaim == null) {
            throw new MetaClaimStoreException("MetaClaim for URI " + claimURI + " was not found");
        }

        return metaClaim;
    }

    @Override
    public List<MetaClaim> getAllMetaClaims() {
        return null;
    }

}
