package io.spring2go.jwtresourceserver.dao;

import io.spring2go.jwtresourceserver.model.Role;


import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends JpaRepository<Role, String> {

    Role findByenname(String ename);
}
