package io.spring2go.jwtresourceserver.serviceImpl;

import io.spring2go.jwtresourceserver.dao.UserRoleRepository;
import io.spring2go.jwtresourceserver.model.Role;
import io.spring2go.jwtresourceserver.model.UserRole;
import io.spring2go.jwtresourceserver.service.RoleService;
import io.spring2go.jwtresourceserver.service.UserRoleService;
import io.spring2go.jwtresourceserver.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserRoleServiceImpl implements UserRoleService {

    @Autowired
    UserRoleRepository userRoleRepository;
    @Autowired
    private RoleService roleService;

    @Override
    public boolean instertByRole(List<String> roles,String userid) {

        for (String role:roles ) {
            Role temprole= roleService.findByenname(role);
            if (temprole == null) {
                break;
            }
            UserRole userRole=new UserRole();
            userRole.setRoleid(temprole.getId());
            userRole.setUserid(userid);
            userRoleRepository.save(userRole);
        }

        return true;
    }

}
