package io.spring2go.jwtresourceserver.secruity;

import java.util.List;
import java.util.stream.Collectors;

import io.spring2go.jwtresourceserver.model.Role;
import io.spring2go.jwtresourceserver.model.WebUser;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public final class JwtUserFactory {

    private JwtUserFactory() {

    }

    public static JwtUser create(WebUser user, List<String> roles) {
        return new JwtUser(
                user.getId(),
                user.getUsername(),
                user.getPassword(),
                user.getEmail(),
                mapToGrantedAuthorities(roles),
                user.getLastPasswordResetDate()
        );
    }

    private static List<GrantedAuthority> mapToGrantedAuthorities(List<String> authorities) {
        return authorities.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }
}

