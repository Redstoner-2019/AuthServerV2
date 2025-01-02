package me.redstoner2019.springbootauth.user;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import me.redstoner2019.springbootauth.security.Password;
import me.redstoner2019.springbootauth.security.Token;

@Entity(name = "authUser")
public class User {
    @Id()
    private long uuid;

    @Column(unique=true, name = "username")
    private String username;

    @Column(name = "displayName")
    private String displayName;

    @Column(name = "password")
    private String password;

    @Column(unique = true, name = "email")
    private String email;

    @Column(name = "multifactor")
    private boolean multifactor;

    @Column(name = "salt")
    private byte[] salt;

    @Column(name = "tokenValidation")
    private String tokenValidation;

    public User(){

    }

    public User(long uuid, String username, String displayName, String password, String email, boolean multifactor, byte[] salt, String tokenValidation) {
        this.uuid = uuid;
        this.username = username;
        this.displayName = displayName;
        this.password = password;
        this.email = email;
        this.multifactor = multifactor;
        this.salt = salt;
        this.tokenValidation = tokenValidation;
    }

    public void updateTokenValidation(){
        //tokenValidation = Token.generateToken(username);
        this.salt = Password.generateSalt();
    }

    public String getTokenValidation() {
        return tokenValidation;
    }

    public void setTokenValidation(String tokenValidation) {
        this.tokenValidation = tokenValidation;
    }

    public boolean isMultifactor() {
        return multifactor;
    }

    public void setMultifactor(boolean multifactor) {
        this.multifactor = multifactor;
    }

    public byte[] getSalt() {
        return salt;
    }

    public void setSalt(byte[] salt) {
        this.salt = salt;
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
