package io.spring2go.jwtresourceserver.serviceImpl;

import io.spring2go.jwtresourceserver.dao.UserRepository;
import io.spring2go.jwtresourceserver.model.Role;
import io.spring2go.jwtresourceserver.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.persistence.Access;
import java.util.List;
@Service
public class UserServiceImpl implements UserService {

    @Autowired
    UserRepository userRepository;

    @Override
    public List<Role> selectRolesByUserId(String userid) {

        return userRepository.selectRolesByUserId(userid);

    }

    @Override
    public List<String> selectRolesNameByUserId(String userid) {

        return userRepository.selectRolesNameByUserId(userid);
    }

}
