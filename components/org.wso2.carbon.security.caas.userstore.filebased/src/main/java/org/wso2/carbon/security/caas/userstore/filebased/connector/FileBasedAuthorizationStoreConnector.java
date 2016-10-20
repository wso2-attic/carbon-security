package org.wso2.carbon.security.caas.userstore.filebased.connector;

import org.wso2.carbon.security.caas.user.core.bean.Action;
import org.wso2.carbon.security.caas.user.core.bean.Group;
import org.wso2.carbon.security.caas.user.core.bean.Permission;
import org.wso2.carbon.security.caas.user.core.bean.Resource;
import org.wso2.carbon.security.caas.user.core.bean.Role;
import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.config.AuthorizationStoreConnectorConfig;
import org.wso2.carbon.security.caas.user.core.exception.AuthorizationStoreException;
import org.wso2.carbon.security.caas.user.core.exception.PermissionNotFoundException;
import org.wso2.carbon.security.caas.user.core.exception.RoleNotFoundException;
import org.wso2.carbon.security.caas.user.core.store.connector.AuthorizationStoreConnector;

import java.util.List;

/**
 * File based implementation of AuthorizationStoreConnector.
 */
public class FileBasedAuthorizationStoreConnector implements AuthorizationStoreConnector {

    private AuthorizationStoreConnectorConfig authorizationStoreConnectorConfig;

//    private BufferedReader bufferedReader;

    @Override
    public void init(AuthorizationStoreConnectorConfig authorizationStoreConnectorConfig)
            throws AuthorizationStoreException {
        this.authorizationStoreConnectorConfig = authorizationStoreConnectorConfig;

//        String userStoreFile = authorizationStoreConnectorConfig.getProperties().getProperty("storeFile");
//
//        if (userStoreFile == null) {
//            throw new AuthorizationStoreException("storeFile property is not provided for file based connector");
//        }
//
//        Path userStorePath = Paths.get(userStoreFile);
//
//        try {
//            bufferedReader = Files.newBufferedReader(userStorePath);
//        } catch (IOException e) {
//            throw new AuthorizationStoreException("Error initializing file based authorization store connector", e);
//        }
    }

    @Override
    public Role.RoleBuilder getRole(String roleId) throws RoleNotFoundException, AuthorizationStoreException {
        return null;
    }

    @Override
    public int getRoleCount() throws AuthorizationStoreException {
        return 0;
    }

    @Override
    public List<Role.RoleBuilder> listRoles(String filterPattern, int offset, int length)
            throws AuthorizationStoreException {
        return null;
    }

    @Override
    public Permission.PermissionBuilder getPermission(Resource resource, Action action)
            throws PermissionNotFoundException, AuthorizationStoreException {
        return null;
    }

    @Override
    public int getPermissionCount() throws AuthorizationStoreException {
        return 0;
    }

    @Override
    public List<Permission.PermissionBuilder> listPermissions(String resourcePattern,
                                                              String actionPattern, int offset, int length)
            throws AuthorizationStoreException {
        return null;
    }

    @Override
    public List<Resource.ResourceBuilder> getResources(String resourcePattern) throws AuthorizationStoreException {
        return null;
    }

    @Override
    public List<Action.ActionBuilder> getActions(String actionPattern) throws AuthorizationStoreException {
        return null;
    }

    @Override
    public List<Role.RoleBuilder> getRolesForUser(String userId, String userDomainName)
            throws AuthorizationStoreException {

        return null;
    }

    @Override
    public List<Role.RoleBuilder> getRolesForGroup(String groupId, String groupDomainName)
            throws AuthorizationStoreException {
        return null;
    }

    @Override
    public List<Permission.PermissionBuilder> getPermissionsForRole(String roleId, Resource resource)
            throws AuthorizationStoreException {
        return null;
    }

    @Override
    public List<Permission.PermissionBuilder> getPermissionsForRole(String roleId, Action action) throws
            AuthorizationStoreException {
        return null;
    }

    @Override
    public Resource.ResourceBuilder addResource(String resourceNamespace, String resourceId, String userId)
            throws AuthorizationStoreException {
        return null;
    }

    @Override
    public Action addAction(String actionNamespace, String actionName) throws AuthorizationStoreException {
        return null;
    }

    @Override
    public Permission.PermissionBuilder addPermission(Resource resource, Action action)
            throws AuthorizationStoreException {
        return null;
    }

    @Override
    public Role.RoleBuilder addRole(String roleName, List<Permission> permissions) throws AuthorizationStoreException {
        return null;
    }

    @Override
    public boolean isUserInRole(String userId, String roleName) throws AuthorizationStoreException {
        return false;
    }

    @Override
    public boolean isGroupInRole(String groupId, String roleName) throws AuthorizationStoreException {
        return false;
    }

    @Override
    public List<User.UserBuilder> getUsersOfRole(String roleId) throws AuthorizationStoreException {
        return null;
    }

    @Override
    public List<Group.GroupBuilder> getGroupsOfRole(String roleId) throws AuthorizationStoreException {
        return null;
    }

    @Override
    public void deleteRole(String roleId) throws AuthorizationStoreException {

    }

    @Override
    public void deletePermission(String permissionId) throws AuthorizationStoreException {

    }

    @Override
    public void deleteResource(Resource resource) throws AuthorizationStoreException {

    }

    @Override
    public void deleteAction(Action action) throws AuthorizationStoreException {

    }

    @Override
    public void updateRolesInUser(String userId, String userDomainName, List<Role> newRoleList) throws
            AuthorizationStoreException {

    }

    @Override
    public void updateUsersInRole(String roleId, List<User> newUserList) throws AuthorizationStoreException {

    }

    @Override
    public void updateRolesInGroup(String groupId, String groupDomainName, List<Role> newRoleList)
            throws AuthorizationStoreException {

    }

    @Override
    public void updateGroupsInRole(String roleId, List<Group> newGroupList) throws AuthorizationStoreException {

    }

    @Override
    public void updatePermissionsInRole(String roleId, List<Permission> newPermissionList)
            throws AuthorizationStoreException {

    }

    @Override
    public void updatePermissionsInRole(String roleId, List<Permission> permissionsToBeAssign,
                                        List<Permission> permissionsToBeUnassign) throws AuthorizationStoreException {

    }

    @Override
    public void updateRolesInUser(String userId, String userDomainName, List<Role> rolesToBeAssign, List<Role>
            rolesToBeUnassign) throws AuthorizationStoreException {

    }

    @Override
    public void updateUsersInRole(String roleId, List<User> usersToBeAssign, List<User> usersToBeUnassign)
            throws AuthorizationStoreException {

    }

    @Override
    public void updateGroupsInRole(String roleId, List<Group> groupToBeAssign, List<Group> groupToBeUnassign)
            throws AuthorizationStoreException {

    }

    @Override
    public void updateRolesInGroup(String groupId, String groupDomainName, List<Role> rolesToBeAssign,
                                   List<Role> rolesToBeUnassigned) throws AuthorizationStoreException {

    }

    @Override
    public AuthorizationStoreConnectorConfig getAuthorizationStoreConfig() {
        return authorizationStoreConnectorConfig;
    }

    @Override
    public String getAuthorizationStoreId() {
        return null;
    }
}
