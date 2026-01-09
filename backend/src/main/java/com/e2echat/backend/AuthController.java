package com.e2echat.backend;

import com.e2echat.backend.database.Person;
import com.e2echat.backend.database.PersonRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
public class AuthController {
    private final PersonRepository personRepository;

    public AuthController(PersonRepository personRepository) {
        this.personRepository = personRepository;
    }

    public record RegisterBody(String username, String publicKey) {}

    /**
     * Returns public key or 404 for username
     */
    @GetMapping("/publickey")
    public ResponseEntity<String> getUserPublicKey(@RequestParam String username) {
        return personRepository.findByUsername(username)
                .map(person -> ResponseEntity.ok(person.getPublicKey()))
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Registers user if available; returns status
     */
    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegisterBody person) {
        if (personRepository.findByUsername(person.username()).isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("User already exists");
        }
        personRepository.save(new Person(person.username(), person.publicKey()));
        return ResponseEntity.status(HttpStatus.CREATED).body("OK");
    }
}
