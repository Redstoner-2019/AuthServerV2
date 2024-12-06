package me.redstoner2019.springbootauth.client;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class ClientController {

    private final ClientJpaRepository clientJpaRepository;

    public ClientController(final ClientJpaRepository clientJpaRepository) {
        this.clientJpaRepository = clientJpaRepository;
    }

    @GetMapping("/client/getAll")
    public List<Client> getClients(){
        return clientJpaRepository.findAll();
    }

    @PostMapping("/client/create")
    public ResponseEntity<Object> createClient(@RequestBody Client client) {
        if(!clientJpaRepository.existsById(client.getId())) {
            clientJpaRepository.save(client);
        }
        return ResponseEntity.ok(client);
    }
}
