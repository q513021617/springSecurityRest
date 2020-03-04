package io.spring2go.jwtresourceserver.model;

import lombok.Data;

import javax.persistence.*;

@Data
@Entity
@Table(name = "user_role")
public class UserRole {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(name = "userid")
    private String userid;

    @Column(name = "roleid")
    private Integer roleid;
}
