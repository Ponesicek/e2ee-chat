package com.e2echat.backend;

import com.e2echat.backend.database.Person;
import com.e2echat.backend.database.PersonRepository;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class AuthController {
    private final PersonRepository personRepository;

    public AuthController(PersonRepository personRepository) {
        this.personRepository = personRepository;
    }

    class registerBody {
        String username;
        String publicKey;
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    String home(@RequestBody registerBody person) {
        personRepository.save(new Person(person.username, person.publicKey));
        return "OK";
    }
}
