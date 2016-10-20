package org.wso2.carbon.security.caas.userstore.filebased.connector;

import org.wso2.carbon.kernel.utils.StringUtils;
import org.wso2.carbon.security.caas.user.core.bean.Attribute;
import org.wso2.carbon.security.caas.user.core.bean.Group;
import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.config.IdentityStoreConnectorConfig;
import org.wso2.carbon.security.caas.user.core.exception.GroupNotFoundException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.exception.UserNotFoundException;
import org.wso2.carbon.security.caas.user.core.store.connector.IdentityStoreConnector;
import org.wso2.carbon.security.caas.userstore.filebased.Constants;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * FileBased IdentityStoreConnector implementation for test usage.
 */
public class FileBasedIdentityStoreConnector implements IdentityStoreConnector {

    String identityStoreConnectorId;
    IdentityStoreConnectorConfig identityStoreConnectorConfig;

    BufferedReader bufferedReader;

    private static final int PRIMARY_ATTRIBUTE_COLUMN = 1;

    /**
     * Attribute order of the csv file. Attribute Name vs position.
     */
    Map<String, Integer> attributeMap;

    /**
     * Number of columns represented in the csv.
     */
    private int numberOfColumns = 7;

    @Override
    public void init(IdentityStoreConnectorConfig identityStoreConnectorConfig)
            throws IdentityStoreException {

        this.identityStoreConnectorConfig = identityStoreConnectorConfig;
        identityStoreConnectorId = identityStoreConnectorConfig.getConnectorId();

        String userStoreFile = identityStoreConnectorConfig.getProperties().getProperty("storeFile");

        if (userStoreFile == null) {
            throw new IdentityStoreException("storeFile property is not provided for file based connector");
        }

        Path userStorePath = Paths.get(userStoreFile);

        populateAttributeMap();

        try {
            bufferedReader = Files.newBufferedReader(userStorePath);
        } catch (IOException e) {
            throw new IdentityStoreException("Error initializing file based identity store connector", e);
        }
    }

    /**
     * Populate attribute order of the csv file.
     */
    private void populateAttributeMap() {
        attributeMap = new HashMap<>();

        attributeMap.put("username", 1);
        attributeMap.put("email", 2);
        attributeMap.put("firstName", 3);
        attributeMap.put("lastName", 4);
        attributeMap.put("address", 5);
        attributeMap.put("phone", 6);
    }

    @Override
    public String getIdentityStoreId() {
        return identityStoreConnectorId;
    }

    @Override
    public User.UserBuilder getUserBuilder(String attributeName, String attributeValue) throws UserNotFoundException,
            IdentityStoreException {
        try {
            bufferedReader.reset();
            String line;
            while (!StringUtils.isNullOrEmpty(line = bufferedReader.readLine())) {

                // Skip comments
                if (line.startsWith(Constants.COMMENT_PREFIX)) {
                    continue;
                }

                String[] userData = line.split(Constants.DELIMITER);

                if (userData.length != numberOfColumns) {
                    throw new IdentityStoreException("Invalid user data found in FileBasedIdentityStoreConnector");
                }

                Integer attributePosition = attributeMap.get(attributeName);

                if (attributePosition == null) {
                    throw new UserNotFoundException("Attribute " + attributeName
                            + " is not found in the FileBasedIndeityStoreConnector");
                }

                // Check if this is the same user
                if (userData[attributePosition].equals(attributeValue)) {
                    return createUserBuilder(userData[PRIMARY_ATTRIBUTE_COLUMN]);
                }
            }

            throw new UserNotFoundException("User " + attributeName + " was not found");
        } catch (IOException e) {
            throw new IdentityStoreException("Error retrieving user mappings", e);
        }
    }

    @Override
    public int getUserCount() throws IdentityStoreException {
        try {
            bufferedReader.reset();

            long count = bufferedReader.lines().count();

            int userCount;

            if (count > Integer.MAX_VALUE) {
                userCount = Integer.MAX_VALUE;
            } else {
                userCount = (int) count;
            }

            return userCount;
        } catch (IOException e) {
            throw new IdentityStoreException("Error getting user count", e);
        }
    }

    @Override
    public List<User.UserBuilder> getUserBuilderList(String attributeName, String filterPattern, int offset, int
            length) throws IdentityStoreException {
        return null;
    }

    @Override
    public List<User.UserBuilder> getAllUserBuilderList(String attributeName, String filterPattern)
            throws IdentityStoreException {
        return null;
    }

    @Override
    public List<Attribute> getUserAttributeValues(String userID) throws IdentityStoreException {
        return null;
    }

    @Override
    public List<Attribute> getUserAttributeValues(String userID, List<String> attributeNames)
            throws IdentityStoreException {
        return null;
    }

    @Override
    public Group.GroupBuilder getGroupBuilder(String attributeName, String attributeValue)
            throws GroupNotFoundException, IdentityStoreException {
        return null;
    }

    @Override
    public int getGroupCount() throws IdentityStoreException {
        return 0;
    }

    @Override
    public List<Group.GroupBuilder> getGroupBuilderList(String filterPattern, int offset, int length) throws
            IdentityStoreException {
        return null;
    }

    @Override
    public List<Attribute> getGroupAttributeValues(String groupId) throws IdentityStoreException {
        return null;
    }

    @Override
    public List<Attribute> getGroupAttributeValues(String groupId, List<String> attributeNames) throws
            IdentityStoreException {
        return null;
    }

    @Override
    public List<Group.GroupBuilder> getGroupBuildersOfUser(String userID) throws IdentityStoreException {
        return null;
    }

    @Override
    public List<User.UserBuilder> getUserBuildersOfGroup(String groupID) throws IdentityStoreException {
        return null;
    }

    @Override
    public boolean isUserInGroup(String userId, String groupId) throws IdentityStoreException {
        return false;
    }

    @Override
    public boolean isReadOnly() throws IdentityStoreException {
        return true;
    }

    @Override
    public IdentityStoreConnectorConfig getIdentityStoreConfig() {
        return identityStoreConnectorConfig;
    }

    /**
     * Create a UserBuilder object from user Id.
     *
     * @param userId The user Id of the user
     * @return A UserBuilder with the given user Id
     */
    private User.UserBuilder createUserBuilder(String userId) {
        return new User.UserBuilder().setUserId(userId);
    }
}
