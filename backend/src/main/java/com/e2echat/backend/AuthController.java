package com.e2echat.backend;

import com.e2echat.backend.database.Person;
import com.e2echat.backend.database.PersonRepository;
import com.e2echat.backend.database.Prekey;
import com.e2echat.backend.database.PrekeyRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class AuthController {
    private final PersonRepository personRepository;
    private final PrekeyRepository prekeyRepository;

    public AuthController(PersonRepository personRepository, PrekeyRepository prekeyRepository) {
        this.personRepository = personRepository;
        this.prekeyRepository = prekeyRepository;
    }

    public record RegisterBody(String username, String masterPublicKey, String[] prekeys) {}

    /**
     * Returns public key or 404 for username
     */
    @GetMapping("/publickey")
    public ResponseEntity<String> getUserPublicKey(@RequestParam String username) {
        return personRepository.findByUsername(username)
                .map(person -> ResponseEntity.ok(person.getMasterPublicKey()))
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Registers user if available; returns status
     */
    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegisterBody person) {
        if(person.prekeys.length != 10) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid prekeys amount");
        }
        if (personRepository.findByUsername(person.username()).isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("User already exists");
        }
        String signedPreKey = person.prekeys[0];
        String signedPreKeySignature = person.prekeys[1];
        Person newPerson = personRepository.save(new Person(person.username, person.masterPublicKey, signedPreKey, signedPreKeySignature));
        List<Prekey> prekeys = new java.util.ArrayList<>(List.of());
        for (int i = 2; i < person.prekeys.length; i++) {
            prekeys.add(new Prekey(newPerson, i - 2, person.prekeys[i]));
        }
        prekeyRepository.saveAll(prekeys);
        return ResponseEntity.status(HttpStatus.CREATED).body("OK");
    }
}
