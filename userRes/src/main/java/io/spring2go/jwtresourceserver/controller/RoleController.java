package io.spring2go.jwtresourceserver.controller;

import io.spring2go.jwtresourceserver.dao.RoleRepository;
import io.spring2go.jwtresourceserver.model.Role;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/role")
@PreAuthorize("hasRole('ADMIN')")
public class RoleController {

    private RoleRepository roleRepository;

    
    @RequestMapping(method = RequestMethod.GET)
    public List<Role> getAllRoles() {
        return roleRepository.findAll();
    }

    @RequestMapping(method = RequestMethod.POST)
    Role addRole(@RequestBody Role addedRole) {
        return roleRepository.save(addedRole);
    }

    @RequestMapping(value = "/{id}", method = RequestMethod.GET)
    public Role getRole(@PathVariable String id) {
        return roleRepository.findOne(id);
    }

    @RequestMapping(value = "/", method = RequestMethod.PUT)
    Role updateRole( @RequestBody Role role) {

        return roleRepository.save(role);
    }

    @RequestMapping(value = "/", method = RequestMethod.DELETE)
    Boolean removeRole(@PathVariable Role role) {

        roleRepository.delete(role);
        return true;
    }

}
