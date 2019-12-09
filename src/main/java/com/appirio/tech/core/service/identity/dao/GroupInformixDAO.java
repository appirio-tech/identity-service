package com.appirio.tech.core.service.identity.dao;

import org.skife.jdbi.v2.sqlobject.Bind;
import org.skife.jdbi.v2.sqlobject.BindBean;
import org.skife.jdbi.v2.sqlobject.GetGeneratedKeys;
import org.skife.jdbi.v2.sqlobject.SqlQuery;
import org.skife.jdbi.v2.sqlobject.SqlUpdate;
import org.skife.jdbi.v2.sqlobject.customizers.RegisterMapperFactory;
import org.skife.jdbi.v2.sqlobject.mixins.Transactional;

import com.appirio.tech.core.api.v3.util.jdbi.TCBeanMapperFactory;
import com.appirio.tech.core.service.identity.representation.SecurityGroup;

/**
 * GroupInformixDAO is used to manage the group in the informix database. 
 * 
 * It's added in  72h TC Identity Service API Enhancements v1.0
 * 
 * @author TCCoder
 * @version 1.0
 *
 */
public abstract class GroupInformixDAO implements Transactional<GroupInformixDAO>  {
    /**
     * Create group
     *
     * @param group the group to create
     * @return the int value
     */
    @RegisterMapperFactory(TCBeanMapperFactory.class)
    @SqlUpdate("INSERT INTO security_groups ("
            + "group_id, description, create_user_id"
            + ") VALUES ("
            + ":g.id, :g.name, :g.createUserId)")
    @GetGeneratedKeys
    public abstract int createGroup(@BindBean("g") SecurityGroup group);
    
    /**
     * Find group by name
     *
     * @param name the name to use
     * @return the SecurityGroup result
     */
    @RegisterMapperFactory(TCBeanMapperFactory.class)
    @SqlQuery(
            "SELECT group_id as id, description as name, create_user_id as createUserId " +
            "FROM security_groups WHERE description = :name"
    )
    public abstract SecurityGroup findGroupByName(@Bind("name") String name);
    
    /**
     * Find group by id
     *
     * @param id the id to use
     * @return the SecurityGroup result
     */
    @RegisterMapperFactory(TCBeanMapperFactory.class)
    @SqlQuery(
            "SELECT group_id as id, description as name, create_user_id as createUserId " +
            "FROM security_groups WHERE group_id = :id"
    )
    public abstract SecurityGroup findGroupById(@Bind("id") long id);
}
