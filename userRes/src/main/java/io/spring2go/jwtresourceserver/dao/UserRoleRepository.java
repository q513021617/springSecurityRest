package io.spring2go.jwtresourceserver.dao;


import io.spring2go.jwtresourceserver.model.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRoleRepository extends JpaRepository<UserRole, String> {



}
