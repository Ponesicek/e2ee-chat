package com.e2echat.backend.database;

import org.springframework.data.repository.Repository;
import org.springframework.security.core.parameters.P;

import java.util.Optional;

public interface PersonRepository extends Repository<Person, Long> {
    Person save(Person person);
    Optional<Person> findByUsername(String username);
}
