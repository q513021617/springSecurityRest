package io.spring2go.jwtresourceserver.dao;

import io.spring2go.jwtresourceserver.model.Role;
import io.spring2go.jwtresourceserver.model.WebUser;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Repository
public interface UserRepository extends JpaRepository<WebUser, String> {
    WebUser findByUsername(final String username);

    @Modifying
    @Query(value="select * \n" +
            "from role\n" +
            "where id in(\n" +
            "select user_role.roleid\n" +
            "from user_role\n" +
            "where user_role.userid:userid\n" +
            ")",nativeQuery = true)
    @Transactional
    List<Role> selectRolesByUserId(@Param("userid") String userid);

    @Modifying
    @Query(value="select role.enname  from role  where id in(\n" +
            "           select user_role.roleid\n" +
            "           from user_role\n" +
            "           where user_role.userid=?1)",nativeQuery = true)
    @Transactional
    List<String> selectRolesNameByUserId(String userid);
}
