package org.wso2.carbon.security.caas.user.core.claim;

import org.wso2.carbon.security.caas.api.util.CarbonSecurityConstants;
import org.wso2.carbon.security.caas.user.core.exception.ConfigurationFileReadException;
import org.wso2.carbon.security.caas.user.core.exception.MetaClaimStoreException;
import org.wso2.carbon.security.caas.user.core.util.FileUtil;

import java.io.IOException;
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
     *
     * @throws ConfigurationFileReadException on error in reading file
     * @throws IOException                    on file not found
     */
    Map<String, MetaClaim> metaClaims;

    public FileBasedMetaClaimStore() throws ConfigurationFileReadException, IOException {

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
