package me.redstoner2019.springbootauth.user;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;

@Entity(name = "my_user")
public class User {
    @Id
    private long uuid;

    @Column(unique=true, name = "username")
    private String username;

    @Column(name = "displayName")
    private String displayName;

    @Column(name = "password")
    private String password;

    @Column(name = "email")
    private String email;

    public User(){

    }

    public User(long uuid, String username, String displayName, String password, String email) {
        this.uuid = uuid;
        this.username = username;
        this.displayName = displayName;
        this.password = password;
        this.email = email;
    }

    public long getUuid() {
        return uuid;
    }

    public void setUuid(long uuid) {
        this.uuid = uuid;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }
}