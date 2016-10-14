package org.wso2.carbon.security.caas.user.core.claim;

import java.util.List;

/**
 * MetaClaimStore interface.
 * Keeps all claim meta data for available claims.
 */
public interface MetaClaimStore {

    public MetaClaim getMetaClaim(String claimURI);

    public List<MetaClaim> getAllMetaClaims();
}
