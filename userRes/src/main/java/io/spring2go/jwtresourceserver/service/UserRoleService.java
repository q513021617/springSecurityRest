package io.spring2go.jwtresourceserver.service;

import java.util.List;

public interface UserRoleService {


    boolean instertByRole(List<String> roles, String userid);

}
