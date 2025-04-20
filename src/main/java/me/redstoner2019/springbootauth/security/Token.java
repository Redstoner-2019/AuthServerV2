package me.redstoner2019.springbootauth.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import me.redstoner2019.springbootauth.user.User;
import me.redstoner2019.springbootauth.user.UserJpaRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.Base64;
import java.util.Date;

@Component
public class Token {

    private final UserJpaRepository userRepository;
    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;
    private Algorithm algorithm;

    @Autowired
    public Token(UserJpaRepository repo) {
        this.userRepository = repo;
    }

    @PostConstruct
    public void init() {
        try {
            String publicKeyEnv = System.getenv("JWT_PUBLIC_KEY");
            String privateKeyEnv = System.getenv("JWT_PRIVATE_KEY");

            if (publicKeyEnv == null || privateKeyEnv == null) {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(2048);
                KeyPair keyPair = keyGen.generateKeyPair();

                privateKey = (RSAPrivateKey) keyPair.getPrivate();
                publicKey = (RSAPublicKey) keyPair.getPublic();

                String pubKeyEncoded = Base64.getEncoder().encodeToString(publicKey.getEncoded());
                String privKeyEncoded = Base64.getEncoder().encodeToString(privateKey.getEncoded());

                System.out.println("Generated new RSA key pair. Set these as env vars:");
                System.out.println("JWT_PUBLIC_KEY=" + pubKeyEncoded);
                System.out.println("JWT_PRIVATE_KEY=" + privKeyEncoded);
            } else {
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                byte[] pubBytes = Base64.getDecoder().decode(publicKeyEnv);
                byte[] privBytes = Base64.getDecoder().decode(privateKeyEnv);

                X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubBytes);
                PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privBytes);

                publicKey = (RSAPublicKey) keyFactory.generatePublic(pubSpec);
                privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privSpec);
            }

            algorithm = Algorithm.RSA256(publicKey, privateKey);

        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize RSA keys", e);
        }
    }

    public String generateToken(String userId, byte[] salt, int validDays) {
        String authHash = Password.hashPassword(userId, salt);
        Date issuedAt = new Date();
        Date expiresAt = (validDays == -1) ? new Date(Long.MAX_VALUE) : new Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24 * validDays);

        return JWT.create()
                .withSubject(userId)
                .withIssuedAt(issuedAt)
                .withExpiresAt(expiresAt)
                .withClaim("auth_hash", authHash)
                .sign(algorithm);
    }

    public boolean isTokenValid(String token) {
        try {
            DecodedJWT decoded = JWT.require(algorithm).build().verify(token);
            String userId = decoded.getSubject();
            String tokenHash = decoded.getClaim("auth_hash").asString();

            User user = userRepository.findById(userId).orElse(null);
            if (user == null) return false;

            String actualHash = Password.hashPassword(userId, user.getSalt());
            return actualHash.equals(tokenHash);
        } catch (Exception e) {
            return false;
        }
    }

    public boolean checkValidity(String token, byte[] salt) {
        try {
            DecodedJWT decoded = JWT.require(algorithm).build().verify(token);
            String userId = decoded.getSubject();
            String tokenHash = decoded.getClaim("auth_hash").asString();
            String actualHash = Password.hashPassword(userId, salt);
            return actualHash.equals(tokenHash);
        } catch (Exception e) {
            return false;
        }
    }

    public int getTokenMode(String token) {
        try {
            getUserId(token);
            return 0;
        } catch (TokenExpiredException e) {
            return 1;
        } catch (JWTDecodeException e) {
            return 2;
        } catch (JWTVerificationException e) {
            return 3;
        }
    }

    public String getUsernameFromToken(String token) {
        return getUserId(token);
    }

    public Date getIssuedAtFromToken(String token) {
        return JWT.require(algorithm).build().verify(token).getIssuedAt();
    }

    public Date getTokenExpiry(String token) {
        return JWT.require(algorithm).build().verify(token).getExpiresAt();
    }

    public String getUserId(String token) {
        return JWT.require(algorithm).build().verify(token).getSubject();
    }
}
