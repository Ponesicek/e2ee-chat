package com.e2echat.backend;

import com.e2echat.backend.database.Person;
import com.e2echat.backend.database.PersonRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {
    private final PersonRepository personRepository;

    public AuthController(PersonRepository personRepository) {
        this.personRepository = personRepository;
    }


    @RequestMapping("/register")
    String home() {
        personRepository.save(new Person("Hello", "world"));
        return "Hello World!";
    }
}
