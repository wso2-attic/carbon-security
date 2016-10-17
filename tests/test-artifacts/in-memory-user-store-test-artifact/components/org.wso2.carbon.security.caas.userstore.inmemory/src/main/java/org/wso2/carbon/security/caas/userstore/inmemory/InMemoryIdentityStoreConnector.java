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

package org.wso2.carbon.security.caas.userstore.inmemory;

import org.wso2.carbon.security.caas.user.core.bean.Attribute;
import org.wso2.carbon.security.caas.user.core.bean.Group;
import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.config.IdentityStoreConnectorConfig;
import org.wso2.carbon.security.caas.user.core.exception.GroupNotFoundException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.exception.UserNotFoundException;
import org.wso2.carbon.security.caas.user.core.store.connector.IdentityStoreConnector;
import org.wso2.carbon.security.caas.userstore.inmemory.util.InMemoryStoreUtil;

import java.util.List;
import java.util.UUID;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;

/**
 * Identity store connector for InMemory based stores.
 *
 * @since 1.0.0
 */
public class InMemoryIdentityStoreConnector implements IdentityStoreConnector {

    @Override
    public void init(String storeId, IdentityStoreConnectorConfig identityStoreConnectorConfig)
            throws IdentityStoreException {
    }

    @Override
    public String getIdentityStoreId() {
        return null;
    }

    @Override
    public User.UserBuilder getUserBuilder(String attributeName, String attributeValue) throws UserNotFoundException,
            IdentityStoreException {

        if (InMemoryStoreUtil.getPassword(attributeValue) != null) {
            return new User.UserBuilder().setUserId(UUID.randomUUID().toString()).setTenantDomain("carbon.super");
        }
        throw new UserNotFoundException("No user found for username: " + attributeValue +
                " in In-Memory identity store.");
    }

    @Override
    public User.UserBuilder getUserBuilder(Callback[] callbacks) throws UserNotFoundException, IdentityStoreException {

        String username = null;
        for (Callback callback : callbacks) {
            if (callback instanceof NameCallback) {
                username = ((NameCallback) callback).getName();
            }
        }

        if (InMemoryStoreUtil.getPassword(username) != null) {
            return new User.UserBuilder().setUserId(UUID.randomUUID().toString()).setTenantDomain("carbon.super");
        }
        throw new UserNotFoundException("No user found for username: " + username + " in In-Memory identity store.");

    }

    @Override
    public List<User.UserBuilder> getUserBuilderList(String attributeName, String filterPattern, int offset, int length)
            throws IdentityStoreException {
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
    public List<Group.GroupBuilder> getGroupBuilderList(String filterPattern, int offset, int length)
            throws IdentityStoreException {
        return null;
    }

    @Override
    public List<Attribute> getGroupAttributeValues(String groupId) throws IdentityStoreException {
        return null;
    }

    @Override
    public List<Attribute> getGroupAttributeValues(String groupId, List<String> attributeNames)
            throws IdentityStoreException {
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
    public boolean isUserInGroup(String userid, String groupId) throws IdentityStoreException {
        return false;
    }

    @Override
    public boolean isReadOnly() throws IdentityStoreException {
        return false;
    }

    @Override
    public IdentityStoreConnectorConfig getIdentityStoreConfig() {
        return null;
    }

    @Override
    public int getUserCount() {
        return 0;
    }

    @Override
    public int getGroupCount() {
        return 0;
    }
}
