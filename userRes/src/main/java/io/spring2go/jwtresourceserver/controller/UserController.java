package io.spring2go.jwtresourceserver.controller;

import io.spring2go.jwtresourceserver.dao.UserRepository;
import io.spring2go.jwtresourceserver.model.WebUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 在 @PreAuthorize 中我们可以利用内建的 SPEL 表达式：比如 'hasRole()' 来决定哪些用户有权访问。
 * 需注意的一点是 hasRole 表达式认为每个角色名字前都有一个前缀 'ROLE_'。所以这里的 'ADMIN' 其实在
 * 数据库中存储的是 'ROLE_ADMIN' 。这个 @PreAuthorize 可以修饰Controller也可修饰Controller中的方法。
 **/
@RestController
@RequestMapping("/users")
public class UserController {
    @Autowired
    private UserRepository repository;


    @RequestMapping(value = "/",method = RequestMethod.GET)
    @PreAuthorize("hasRole('USER')")
    public List<WebUser> getUsers() {
        return repository.findAll();
    }

    @PreAuthorize("hasRole('ADMIN')")
    @RequestMapping(method = RequestMethod.POST)
    WebUser addUser(@RequestBody WebUser addedUser) {
        return repository.save(addedUser);
    }

    @PostAuthorize("hasRole('ADMIN','USER')")
    @RequestMapping(value = "/{id}", method = RequestMethod.GET)
    public WebUser getUser(@PathVariable String id) {
        return repository.findOne(id);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @RequestMapping(value = "/{id}", method = RequestMethod.PUT)
    WebUser updateUser(@PathVariable String id, @RequestBody WebUser updatedUser) {
        updatedUser.setId(id);
        return repository.save(updatedUser);
    }

    @PreAuthorize("hasRole('ADMIN','USER')")
    @RequestMapping(value = "/{id}", method = RequestMethod.DELETE)
    WebUser removeUser(@PathVariable String id) {
        WebUser deletedUser = repository.findOne(id);
        repository.delete(id);
        return deletedUser;
    }

    @PostAuthorize("returnObject.username == principal.username or hasRole('ADMIN','USER')")
    @RequestMapping(value = "/name/{username}",method = RequestMethod.GET)
    public WebUser getUserByUsername(@PathVariable(value="username") String username) {


        return repository.findByUsername(username);
    }

}
