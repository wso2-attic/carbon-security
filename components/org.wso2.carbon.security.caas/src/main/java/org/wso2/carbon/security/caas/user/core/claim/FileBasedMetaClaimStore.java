package org.wso2.carbon.security.caas.user.core.claim;

import org.wso2.carbon.security.caas.user.core.exception.MetaClaimStoreException;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.introspector.BeanAccess;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
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

    public FileBasedMetaClaimStore(String filepath) throws IOException {
        Path file = Paths.get(filepath);

        if (Files.exists(file)) {

            try (Reader in = new InputStreamReader(Files.newInputStream(file), StandardCharsets.UTF_8)) {
                Yaml yaml = new Yaml();
                yaml.setBeanAccess(BeanAccess.FIELD);
                MetaClaimStoreFile metaClaimStoreFile = yaml.loadAs(in, MetaClaimStoreFile.class);


                this.metaClaims = metaClaimStoreFile.getClaims().stream()
                        .collect(Collectors.toMap(MetaClaim::getClaimURI, metaClaim -> metaClaim));

            } catch (IOException e) {
                throw new RuntimeException("Error while loading claim store " + filepath, e);
            }
        } else {
            throw new IOException("Claim Store file " + filepath + "' is not available.");
        }
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
