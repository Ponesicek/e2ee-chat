package com.e2echat.backend.database;

import org.springframework.data.repository.Repository;

import java.util.Optional;

public interface PersonRepository extends Repository<Person, Long> {

    Person save(Person person);
}
