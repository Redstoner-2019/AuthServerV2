package me.redstoner2019.springbootauth.security;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class Password {
    private static final int SALT_LENGTH = 16; // 16 bytes
    private static final int HASH_ITERATIONS = 65536;
    private static final int HASH_LENGTH = 128; // 128 bits

    public static String hashPassword(String password, byte[] salt){
        try{
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, HASH_ITERATIONS, HASH_LENGTH);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hash = keyFactory.generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(hash);
        }catch (Exception e){
            throw new RuntimeException(e);
        }
    }

    public static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);
        return salt;
    }
}
