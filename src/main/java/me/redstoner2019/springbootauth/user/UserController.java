package me.redstoner2019.springbootauth.user;

import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import me.redstoner2019.springbootauth.mail.Mail;
import me.redstoner2019.springbootauth.security.Password;
import me.redstoner2019.springbootauth.security.Token;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.*;

@RestController
public class UserController {
    public final UserJpaRepository userJpaRepository;
    public static HashMap<Long,String> confirmationCodes = new HashMap<>();
    public static HashMap<Long,User> confirmationUser = new HashMap<>();
    public static HashMap<Long,User> confirmation = new HashMap<>();
    public static HashMap<Long,Long> expiration = new HashMap<>();
    public static List<String> activeTokens = new ArrayList<>();

    public UserController(UserJpaRepository userJpaRepository) {
        this.userJpaRepository = userJpaRepository;
        fillWithTestData();
    }

    @PostMapping
    public void empty(@RequestBody String user) {
        System.out.println(user);
    }

    @PostMapping("/user/create")
    public ResponseEntity<String> create(@RequestBody String jsonString) {
        try{
            JSONObject json = new JSONObject(jsonString);

            System.out.println(json.toString(3));

            User user = new User();
            if(json.getString("type").equals("creation")){
                if(json.has("user")){
                    json = json.getJSONObject("user");
                    do {
                        user.setUuid(Math.abs(new Random().nextLong()));
                    } while (userJpaRepository.existsById(user.getUuid()));

                    user.setUsername(json.getString("username"));
                    user.setDisplayName(json.getString("displayName"));
                    user.setEmail(json.getString("email"));
                    user.updateTokenValidation();

                    String unencryptedPassword = json.getString("password");

                    byte[] salt = Password.generateSalt();

                    String pwd = Password.hashPassword(unencryptedPassword, salt);

                    user.setPasswordPlain(unencryptedPassword);
                    user.setPassword(pwd);
                    user.setSalt(salt);

                    if(userJpaRepository.findByUsername(user.getUsername()).isEmpty()){
                        if(!userJpaRepository.findByEmail(user.getEmail()).isEmpty()){
                            JSONObject response = new JSONObject();
                            response.put("message","email-already-exists");
                            return ResponseEntity.ok(response.toString());
                        }
                        long confirmId = new Random().nextInt();
                        String confirmCode = "";
                        for (int i = 0; i < 3; i++) {
                            confirmCode += new Random().nextInt(10);
                        }
                        confirmCode+="-";
                        for (int i = 0; i < 3; i++) {
                            confirmCode += new Random().nextInt(10);
                        }

                        confirmationCodes.put(confirmId,confirmCode);
                        confirmationUser.put(confirmId,user);
                        expiration.put(confirmId,System.currentTimeMillis() + (15*60*1000));

                        Mail.sendCreateEmail(user.getEmail(),confirmCode,user.getUsername(),user.getDisplayName());

                        JSONObject response = new JSONObject();
                        response.put("message","account-in-confirmation");
                        response.put("confirm-id",confirmId);
                        System.out.println("Confirm Code: " + confirmCode);

                        return ResponseEntity.ok(response.toString());
                    } else {
                        JSONObject response = new JSONObject();
                        response.put("message","username-already-exists");
                        return ResponseEntity.ok(response.toString());
                    }
                } else {
                    return ResponseEntity.badRequest().body("Missing User.");
                }
            } else if(json.getString("type").equals("confirm")) {
                if(json.has("confirmationId") && json.has("confirmationCode")){
                    long confirmId = json.getLong("confirmationId");
                    String confirmCode = json.getString("confirmationCode");
                    if(confirmationCodes.containsKey(confirmId)){
                        if(System.currentTimeMillis() - expiration.get(confirmId) > 0){
                            JSONObject response = new JSONObject();
                            response.put("message","code-expired");
                            return ResponseEntity.ok(response.toString());
                        }
                        if(Objects.equals(confirmationCodes.get(confirmId), confirmCode)){
                            confirmationCodes.remove(confirmId);
                            userJpaRepository.save(confirmationUser.get(confirmId));
                            confirmationUser.remove(confirmId);
                            expiration.remove(confirmId);

                            JSONObject response = new JSONObject();
                            response.put("message","user-created");
                            return ResponseEntity.ok(response.toString());
                        } else {
                            JSONObject response = new JSONObject();
                            response.put("message","incorect-confirmation-code");
                            return ResponseEntity.ok(response.toString());
                        }
                    } else {
                        JSONObject response = new JSONObject();
                        response.put("message","confirm-id-not-found");
                        return ResponseEntity.ok(response.toString());
                    }
                } else {
                    return ResponseEntity.badRequest().body("Missing confirmationId or confirmationCode.");
                }
            } else {
                return ResponseEntity.badRequest().body("Type not implemented.");
            }
        } catch (JSONException e){
            JSONObject response = new JSONObject();
            response.put("message", e.getMessage());
            return ResponseEntity.status(200).body(response.toString());
            //return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/user/findAll")
    public ResponseEntity<String> getAllUsers(){
        List<User> users = userJpaRepository.findAll();
        JSONArray userArray = new JSONArray();
        for (User u : users) {
            JSONObject user = new JSONObject();
            user.put("username",u.getUsername());
            user.put("displayName",u.getDisplayName());
            user.put("id",u.getUuid());
            userArray.put(user);
        }
        return ResponseEntity.ok(userArray.toString());
    }

    @PostMapping("/user/findByUsername")
    public ResponseEntity<String> fromUsername(@RequestBody String body) {
        try{
            JSONObject jsonBody = new JSONObject(body);
            User u;
            Optional<User> ou = userJpaRepository.findByUsername(jsonBody.getString("username"));
            JSONObject response = new JSONObject();

            if(ou.isPresent()){
                u = ou.get();
            } else {
                response.put("message","not-found");
                return ResponseEntity.ok().body(response.toString());
            }

            JSONObject user = new JSONObject();
            user.put("username",u.getUsername());
            user.put("displayName",u.getDisplayName());
            user.put("id",u.getUuid());

            response.put("user",user);
            response.put("message","found");
            return ResponseEntity.ok().body(response.toString());
        }catch (JSONException e){
            JSONObject response = new JSONObject();
            response.put("error",e.getMessage());
            return ResponseEntity.badRequest().body(response.toString());
        }
    }

    @PostMapping("/user/findById")
    public ResponseEntity<String> fromId(@RequestBody String body) {
        try{
            JSONObject jsonBody = new JSONObject(body);

            Optional<User> ou = userJpaRepository.findById(jsonBody.getLong("id"));

            User u;

            JSONObject response = new JSONObject();

            if(ou.isEmpty()){
                response.put("message","not-found");
                return ResponseEntity.ok().body(response.toString());
            } else {
                u = ou.get();
            }

            JSONObject user = new JSONObject();
            user.put("username",u.getUsername());
            user.put("displayName",u.getDisplayName());
            user.put("id",u.getUuid());

            response.put("user",user);
            response.put("message","found");
            return ResponseEntity.ok().body(response.toString());
        }catch (JSONException e){
            JSONObject response = new JSONObject();
            response.put("error",e.getMessage());
            return ResponseEntity.badRequest().body(response.toString());
        }
    }

    @PostMapping("/tokenInfo")
    public ResponseEntity<String> tokenInfo(@RequestBody String body) {
        try{
            JSONObject jsonBody = new JSONObject(body);
            String TOKEN = jsonBody.getString("token");

            Date issued = Token.getIssuedAtFromToken(TOKEN);
            Date expiry = Token.getTokenExpiry(TOKEN);

            String username = Token.getUsernameFromToken(TOKEN);

            User user = userJpaRepository.findByUsername(username).get();

            JSONObject response = new JSONObject();
            response.put("username",username);
            response.put("displayname",user.getDisplayName());
            response.put("email",user.getEmail());
            response.put("issued",issued.getTime());
            response.put("expiry",expiry.getTime());
            response.put("issued-string",issued.toString());
            response.put("expiry-string",expiry.toString());
            return ResponseEntity.ok().body(response.toString());
        }catch (Exception e){
            JSONObject response = new JSONObject();
            response.put("error",e.getMessage());
            return ResponseEntity.badRequest().body(response.toString());
        }
    }

    @PostMapping("/verifyToken")
    public ResponseEntity<String> isValid(@RequestBody String body) {
        try{
            JSONObject jsonBody = new JSONObject(body);

            int status;

            JSONObject response = new JSONObject();

            try {
                String userId = Token.getUsernameFromToken(jsonBody.getString("token"));
                if(!isValidToken(jsonBody.getString("token"))){
                    response.put("message","Token is invalid!");
                    status = 4;
                } else {
                    response.put("message","Token is valid! User ID: " + userId);
                    status = 0;
                }
            } catch (TokenExpiredException e) {
                response.put("message","Token has expired!");
                status = 1;
            } catch (JWTDecodeException e) {
                response.put("message","Token structure is invalid!");
                status = 2;
            } catch (JWTVerificationException e) {
                response.put("message","Token is invalid!");
                status = 3;
            }

            response.put("status",status);

            return ResponseEntity.ok().body(response.toString());
        }catch (Exception e){
            JSONObject response = new JSONObject();
            response.put("error",e.getMessage());
            return ResponseEntity.badRequest().body(response.toString());
        }
    }

    @PostMapping("/loginConfirmation")
    public ResponseEntity<String> loginConfirmation(@RequestBody String body) {
        try{
            JSONObject jsonBody = new JSONObject(body);

            long confirmId = jsonBody.getLong("confirmId");
            String code = jsonBody.getString("code");
            int days = jsonBody.optInt("days",3);

            JSONObject response = new JSONObject();

            if(confirmationCodes.containsKey(confirmId)){
                if(confirmationCodes.get(confirmId).equals(code)){
                    if(System.currentTimeMillis() - expiration.get(confirmId) > 0){
                        response.put("message","code-expired");
                        return ResponseEntity.ok(response.toString());
                    }
                    User user = confirmation.get(confirmId);
                    response.put("message","success");

                    confirmationCodes.remove(confirmId);
                    confirmation.remove(confirmId);

                    String TOKEN = Token.generateToken(user.getUsername(), user.getSalt(), days);
                    //String TOKEN = Token.generateToken(user.getUsername());

                    response.put("token",TOKEN);
                    activeTokens.add(TOKEN);
                } else {
                    response.put("message","incorect-confirmation-code");
                }
            } else {
                response.put("message","confirm-id-not-found");
            }

            return ResponseEntity.ok().body(response.toString());
        }catch (JSONException e){
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    ///Default
    @PostMapping("/error")
    public ResponseEntity<String> error(@RequestBody String body) {
        try{
            JSONObject jsonBody = new JSONObject(body);

            /*
             if(request.has("token") && request.has("displayname")){
                String token = request.getString("token");

                if(!isValidToken(token)){
                    response.put("message","invalid-token");
                    response.put("reason",Token.getTokenMode(token));
                    return ResponseEntity.status(403).body(response.toString());
                }

                String username = Token.getUsernameFromToken(token);
            }

            */

            return ResponseEntity.badRequest().body(jsonBody.getString("message"));
        }catch (JSONException e){
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/test")
    public ResponseEntity<String> test(@RequestBody String body) {
        return ResponseEntity.ok().body(body);
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody String body) {
        try{
            JSONObject jsonBody = new JSONObject(body);
            String username = jsonBody.getString("username");
            String password = jsonBody.getString("password");
            int days = jsonBody.optInt("days",3);

            System.out.println(username + " - " + password);

            Optional<User> ou = userJpaRepository.findByUsername(username);
            User u;
            if(ou.isPresent()){
                u = ou.get();
                System.out.println(u.getPasswordPlain());
                if(u.getPasswordPlain() == null){
                    u.setPasswordPlain(password);
                    userJpaRepository.save(u);
                }
            } else {
                ou = userJpaRepository.findByEmail(username);
                if(ou.isPresent()){
                    u = ou.get();
                    System.out.println(u.getPasswordPlain());
                    if(u.getPasswordPlain() == null){
                        u.setPasswordPlain(password);
                        userJpaRepository.save(u);
                    }
                } else {
                    JSONObject response = new JSONObject();
                    response.put("message","user-not-found");
                    return ResponseEntity.ok().body(response.toString());
                }
            }

            byte[] salt = u.getSalt();
            String encryptedPassword = Password.hashPassword(password,salt);

            if(encryptedPassword.equals(u.getPassword())){
                if(u.isMultifactor()){
                    long confirmId = new Random().nextInt();
                    String confirmCode = "";
                    for (int i = 0; i < 3; i++) {
                        confirmCode += new Random().nextInt(10);
                    }
                    confirmCode+="-";
                    for (int i = 0; i < 3; i++) {
                        confirmCode += new Random().nextInt(10);
                    }

                    confirmId = Math.abs(confirmId);

                    confirmationCodes.put(confirmId,confirmCode);
                    confirmation.put(confirmId, u);
                    expiration.put(confirmId,System.currentTimeMillis() + (2*60*1000));

                    JSONObject response = new JSONObject();
                    response.put("message","authenticate");

                    response.put("auth-id",confirmId);
                    System.out.println(confirmCode);

                    Mail.sendLoginEmail(u.getEmail(),confirmCode,u.getUsername(),u.getDisplayName());

                    return ResponseEntity.ok().body(response.toString());
                }

                JSONObject response = new JSONObject();
                response.put("message","success");

                String TOKEN = Token.generateToken(u.getUsername(), u.getSalt(), days);
                //String TOKEN = Token.generateToken(u.getUsername());
                activeTokens.add(TOKEN);

                response.put("token",TOKEN);
                return ResponseEntity.ok().body(response.toString());
            } else {
                JSONObject response = new JSONObject();
                response.put("message","incorrect-password");
                return ResponseEntity.ok().body(response.toString());
            }
        }catch (JSONException e){
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    public void fillWithTestData(){
        try {
            User user = new User();
            user.setSalt(Password.generateSalt());
            user.setPassword(Password.hashPassword("test",user.getSalt()));
            user.setUuid(0);
            user.setEmail("redstoner.2020@gmail.com");
            user.setUsername("redstoner_2019");
            user.setDisplayName("Redstoner_2019");
            user.setMultifactor(true);
            userJpaRepository.save(user);

            user = new User();
            user.setSalt(Password.generateSalt());
            user.setPassword(Password.hashPassword("test",user.getSalt()));
            user.setUuid(1);
            user.setEmail("h.kaplan@optadata.de");
            user.setUsername("halulzen");
            user.setDisplayName("HaLuLzEn");
            user.setMultifactor(true);
            userJpaRepository.save(user);
        }catch (Exception e){

        }

        /*try{
            user = new User();
            user.setSalt(Password.generateSalt());
            user.setPassword(Password.hashPassword("test",user.getSalt()));
            user.setUuid(2);
            user.setEmail("redstoner.2020@gmail.com");
            user.setUsername("testuser");
            user.setDisplayName("TestUser");
            userJpaRepository.save(user);
            System.out.println("Complete");
        }catch (Exception e){
            System.out.println("Failed to create user");
            //e.printStackTrace();
        }*/
    }

    @PostMapping("/changeDisplayname")
    public ResponseEntity<String> changeDisplayname(@RequestBody String body) {
        try{
            JSONObject request = new JSONObject(body);

            JSONObject response = new JSONObject();

            if(request.has("token") && request.has("displayname")){
                String token = request.getString("token");

                if(!isValidToken(token)){
                    response.put("message","invalid-token");
                    response.put("reason",Token.getTokenMode(token));
                    return ResponseEntity.status(403).body(response.toString());
                }

                String username = Token.getUsernameFromToken(token);

                Optional<User> ou = userJpaRepository.findByUsername(username);

                User u;

                if(ou.isPresent()){
                    u = ou.get();
                } else {
                    response.put("message","unexpected-server-error");
                    response.put("error","changeDisplayname-user-not-found-from-token");
                    return ResponseEntity.status(500).body(response.toString());
                }

                u.setDisplayName(request.getString("displayname"));

                userJpaRepository.save(u);
            }

            return ResponseEntity.ok().body(response.toString());
        }catch (JSONException e){
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/changeEmail")
    public ResponseEntity<String> changeEmail(@RequestBody String body) {
        try{
            JSONObject request = new JSONObject(body);

            JSONObject response = new JSONObject();

            if(request.has("token") && request.has("email")){
                String token = request.getString("token");

                if(!isValidToken(token)){
                    response.put("message","invalid-token");
                    response.put("reason",Token.getTokenMode(token));
                    return ResponseEntity.status(403).body(response.toString());
                }

                String username = Token.getUsernameFromToken(token);
                Optional<User> ou = userJpaRepository.findByUsername(username);

                User u;

                if(ou.isPresent()){
                    u = ou.get();
                } else {
                    response.put("message","unexpected-server-error");
                    response.put("error","changeDisplayname-user-not-found-from-token");
                    return ResponseEntity.status(500).body(response.toString());
                }

                u.setEmail(request.getString("email"));

                userJpaRepository.save(u);
            }

            return ResponseEntity.ok().body(response.toString());
        }catch (JSONException e){
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/changeMultifactor")
    public ResponseEntity<String> changeMultifactor(@RequestBody String body) {
        try{
            JSONObject request = new JSONObject(body);

            JSONObject response = new JSONObject();

            if(request.has("token") && request.has("multifactor")){
                String token = request.getString("token");

                if(!isValidToken(token)){
                    response.put("message","invalid-token");
                    response.put("reason",Token.getTokenMode(token));
                    return ResponseEntity.status(403).body(response.toString());
                }

                String username = Token.getUsernameFromToken(token);
                Optional<User> ou = userJpaRepository.findByUsername(username);

                User u;

                if(ou.isPresent()){
                    u = ou.get();
                } else {
                    response.put("message","unexpected-server-error");
                    response.put("error","changeDisplayname-user-not-found-from-token");
                    return ResponseEntity.status(500).body(response.toString());
                }

                u.setMultifactor(request.getBoolean("multifactor"));

                userJpaRepository.save(u);
            }

            return ResponseEntity.ok().body(response.toString());
        }catch (JSONException e){
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/changePassword")
    public ResponseEntity<String> changePassword(@RequestBody String body) {
        try{
            JSONObject request = new JSONObject(body);
            if(request.has("token") && request.has("password")){
                String token = request.getString("token");

                JSONObject response = new JSONObject();

                if(!isValidToken(token)){
                    response.put("message","invalid-token");
                    response.put("reason",Token.getTokenMode(token));
                    return ResponseEntity.status(403).body(response.toString());
                }

                String username = Token.getUsernameFromToken(token);
                Optional<User> ou = userJpaRepository.findByUsername(username);

                User u;

                if(ou.isPresent()){
                    u = ou.get();
                } else {
                    response.put("message","unexpected-server-error");
                    response.put("error","changeDisplayname-user-not-found-from-token");
                    return ResponseEntity.status(500).body(response.toString());
                }

                u.setSalt(Password.generateSalt());

                String password = Password.hashPassword(request.getString("password"),u.getSalt());

                u.setPassword(password);

                userJpaRepository.save(u);
            }
            return ResponseEntity.ok().build();
        }catch (JSONException e){
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    public boolean isValidToken(String token){
        if(Token.getTokenMode(token) != 0){
            return false;
        }
        User u = userJpaRepository.findByUsername(Token.getUsernameFromToken(token)).get();
        return Token.checkValidity(token, u.getSalt());
        /*User u = userJpaRepository.findByUsername(Token.getUsernameFromToken(token));

        String tokenValidation = Token.getSecretFromToken(token);

        return u.getTokenValidation().equals(tokenValidation);*/
    }
}
