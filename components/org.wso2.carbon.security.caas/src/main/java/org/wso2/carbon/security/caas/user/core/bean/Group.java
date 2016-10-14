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

package org.wso2.carbon.security.caas.user.core.bean;

import org.wso2.carbon.security.caas.user.core.exception.StoreException;

/**
 * Group represents a group of users.
 */
public class Group {

    /**
     * Unique group id.
     */
    private String groupId;

    /**
     * Domain in which the group belongs.
     */
    private Domain domain;

    private Group(String groupId, Domain domain) {

        this.groupId = groupId;
        this.domain = domain;
    }

    /**
     * Get the group id.
     *
     * @return Group id.
     */
    public String getGroupId() {
        return groupId;
    }

    /**
     * Get this group's domain.
     *
     * @return Domain of this group.
     */
    public Domain getDomain() {
        return domain;
    }

    /**
     * Builder for group bean.
     */
    public static class GroupBuilder {

        private String groupId;
        private Domain domain;

        public String getGroupId() {
            return groupId;
        }

        public Domain getDomain() {
            return domain;
        }

        public GroupBuilder setGroupId(String groupId) {
            this.groupId = groupId;
            return this;
        }

        public GroupBuilder setDomain(Domain domain) {
            this.domain = domain;
            return this;
        }

        public Group build() {

            if (groupId == null || domain == null) {
                throw new StoreException("Required data missing for building group.");
            }

            return new Group(groupId, domain);
        }
    }
}
