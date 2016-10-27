package org.wso2.carbon.security.caas.user.core.user;

import org.wso2.carbon.security.caas.api.util.CarbonSecurityConstants;
import org.wso2.carbon.security.caas.user.core.exception.UserManagerException;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * File based UserManager implementation.
 */
public class FileBasedUserManager implements UserManager {

    private static final String USER_MAPPING_FILE_NAME = "user-mapping.csv";
    private static final String DELIMITER = ",";

    private Path userMappingFile;

    public FileBasedUserManager() throws UserManagerException {
        userMappingFile = Paths.get(CarbonSecurityConstants.getCarbonHomeDirectory().toString(), "conf",
                "security", USER_MAPPING_FILE_NAME);
    }

    @Override
    public String getUniqueUserId(String connectorUserId, String connectorId) throws UserManagerException {

        try (BufferedReader bufferedReader = Files.newBufferedReader(userMappingFile)) {

            String line;
            while ((line = bufferedReader.readLine()) != null) {
                String[] mappings = line.split(DELIMITER);

                if (mappings.length != 3) {
                    throw new UserManagerException("Invalid user mapping found in FileBasedUserManager");
                }

                if (connectorUserId.equals(mappings[1].trim()) && connectorId.equals(mappings[2].trim())) {
                    return mappings[0];
                }
            }

            throw new UserManagerException("uniqueUserId not found for connectorUserId : " + connectorUserId);
        } catch (IOException e) {
            throw new UserManagerException("Error retrieving user mappings", e);
        }
    }

    @Override
    public String getConnectorUserId(String uniqueUserId, String connectorId) throws UserManagerException {

        try (BufferedReader bufferedReader = Files.newBufferedReader(userMappingFile)) {

            String line;
            while ((line = bufferedReader.readLine()) != null) {
                String[] mappings = line.split(DELIMITER);

                if (mappings.length != 3) {
                    throw new UserManagerException("Invalid user mapping found in FileBasedUserManager");
                }

                if (uniqueUserId.equals(mappings[0].trim()) && connectorId.equals(mappings[2].trim())) {
                    return mappings[1];
                }
            }

            throw new UserManagerException("connectorUserId not found for uniqueUserId : " + uniqueUserId);
        } catch (IOException e) {
            throw new UserManagerException("Error retrieving user mappings", e);
        }
    }
}
