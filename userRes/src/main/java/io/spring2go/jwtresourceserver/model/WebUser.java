package io.spring2go.jwtresourceserver.model;

import lombok.Data;



import javax.persistence.*;
import java.io.Serializable;

import java.sql.Date;

import java.util.List;

@Data
@Entity
@Table(name = "user")
public class WebUser implements Serializable {

    @Id
    private String id;

    @Column(name = "username")
    String username;

    @Column(name = "password")
    String password;

    @Column(name = "phone")
    String phone;
    //1，男  2，女
    @Column(name = "sex")
    Integer sex;

    @Column(name = "email")
    String email;

    @Column(name = "updated")
    private Date lastPasswordResetDate;

    @Column(name = "created")
    Date created;

}
