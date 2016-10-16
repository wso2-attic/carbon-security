package org.wso2.carbon.security.caas.user.core.claim;

import org.wso2.carbon.security.caas.user.core.exception.MetaClaimStoreException;

import java.util.List;

/**
 * MetaClaimStore interface.
 * Keeps all claim meta data for available claims.
 */
public interface MetaClaimStore {

    /**
     * Get MetaClaim for a given claimURI.
     *
     * @param claimURI Claim URI of the required meta data
     * @return MetaClaim
     * @throws MetaClaimStoreException
     */
    public MetaClaim getMetaClaim(String claimURI) throws MetaClaimStoreException;

    /**
     * Get meta data of all the supported claims.
     *
     * @return List of all MetaClaims
     */
    public List<MetaClaim> getAllMetaClaims();
}
