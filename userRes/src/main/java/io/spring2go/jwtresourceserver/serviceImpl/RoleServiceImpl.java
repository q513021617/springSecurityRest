package io.spring2go.jwtresourceserver.serviceImpl;

import io.spring2go.jwtresourceserver.dao.RoleRepository;
import io.spring2go.jwtresourceserver.model.Role;
import io.spring2go.jwtresourceserver.service.RoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class RoleServiceImpl implements RoleService {

    @Autowired
    RoleRepository roleRepository;

    @Override
    public Role findByenname(String ename) {

        return roleRepository.findByenname(ename);
    }
}
