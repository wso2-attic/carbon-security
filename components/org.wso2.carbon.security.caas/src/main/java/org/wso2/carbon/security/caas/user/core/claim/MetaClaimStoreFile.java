package org.wso2.carbon.security.caas.user.core.claim;

import java.util.List;

/**
 * MetaClaimStore file object used for FileBasedMetaClaimStore initialization.
 */
public class MetaClaimStoreFile {

    private List<MetaClaim> claims;

    public List<MetaClaim> getClaims() {
        return claims;
    }

    public void setClaims(List<MetaClaim> claims) {
        this.claims = claims;
    }
}
