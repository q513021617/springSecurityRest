package io.spring2go.jwtresourceserver.service;

import io.spring2go.jwtresourceserver.model.Role;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface UserService {

    List<Role> selectRolesByUserId(@Param("userid") String userid);
    List<String> selectRolesNameByUserId(@Param("userid") String userid);
}
