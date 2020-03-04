package io.spring2go.jwtresourceserver.service;


import io.spring2go.jwtresourceserver.model.WebUser;

public interface AuthService {
    WebUser register(WebUser userToAdd);
    String login(String username, String password);
    String refresh(String oldToken);
}
