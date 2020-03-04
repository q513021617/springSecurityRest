package io.spring2go.jwtresourceserver.service;


import io.spring2go.jwtresourceserver.model.Role;

public interface RoleService {

    Role findByenname(String ename);
}
