package me.redstoner2019.springbootauth.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Date;

public class Token {
    private static final String SECRET_KEY = generateSecretKey(256); // Store securely in environment variables
    private static final long TOKEN_EXPIRY = 1000 * 60 * 60 * 72; // 24 hours in milliseconds

    public static String generateToken(String userId) {
        return JWT.create()
                .withSubject(userId) // User-specific data
                .withExpiresAt(new Date(System.currentTimeMillis() + TOKEN_EXPIRY)) // Token expiration
                .sign(Algorithm.HMAC256(SECRET_KEY)); // Sign the token
    }

    public static String getUsernameFromToken(String token) {
        Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY);
        JWTVerifier verifier = JWT.require(algorithm).build();
        DecodedJWT decodedJWT = verifier.verify(token);

        return decodedJWT.getSubject(); // Extract the subject (user ID)
    }

    public static String generateSecretKey(int keyLengthBytes) {
        byte[] key = new byte[keyLengthBytes];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(key);
        return Base64.getEncoder().encodeToString(key); // Encode to Base64 for easy storage
    }
}
