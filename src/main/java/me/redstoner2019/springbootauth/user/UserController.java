package me.redstoner2019.springbootauth.user;

import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Random;

@RestController
public class UserController {
    public final UserJpaRepository userJpaRepository;
    public static HashMap<Long,Integer> confirmationCodes = new HashMap<>();
    public static HashMap<Long,User> confirmationUser = new HashMap<>();

    public UserController(UserJpaRepository userJpaRepository) {
        this.userJpaRepository = userJpaRepository;
    }

    @PostMapping("/user/findAll")
    public ResponseEntity<List<User>> findAll() {
        List<User> users = userJpaRepository.findAll();
        return ResponseEntity.ok(users);
    }

    @PostMapping("/user/create")
    public ResponseEntity<String> create(@RequestBody String jsonString) {
        try{
            JSONObject json = new JSONObject(jsonString);

            User user = new User();
            if(json.getString("type").equals("creation")){
                if(json.has("user")){
                    json = json.getJSONObject("user");
                    do {
                        user.setUuid(Math.abs(new Random().nextLong()));
                    } while (userJpaRepository.existsById(user.getUuid()));

                    user.setUsername(json.getString("username"));
                    user.setPassword(json.getString("password"));
                    user.setDisplayName(json.getString("displayName"));
                    user.setEmail(json.getString("email"));

                    if(userJpaRepository.findByUsername(user.getUsername()) == null){
                        long confirmId = new Random().nextLong();
                        int confirmCode = new Random().nextInt(9999);

                        confirmationCodes.put(confirmId,confirmCode);
                        confirmationUser.put(confirmId,user);

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
                    int confirmCode = json.getInt("confirmationCode");
                    if(confirmationCodes.containsKey(confirmId)){
                        if(confirmationCodes.get(confirmId) == confirmCode){
                            confirmationCodes.remove(confirmId);
                            userJpaRepository.save(confirmationUser.get(confirmId));
                            confirmationUser.remove(confirmId);

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
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/user/fromId")
    public ResponseEntity<String> fromId(@RequestBody String body) {
        try{
            JSONObject jsonBody = new JSONObject(body);
            User user = userJpaRepository.findByUsername(jsonBody.getString("username"));
            JSONObject response = new JSONObject();
            return ResponseEntity.ok().body(response.toString());
        }catch (JSONException e){
            JSONObject response = new JSONObject();
            response.put("error",e.getMessage());
            return ResponseEntity.badRequest().body(response.toString());
        }
    }
}
