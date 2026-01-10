package com.e2echat.backend.database;

import org.springframework.data.repository.Repository;

import java.util.List;
import java.util.Optional;

public interface PrekeyRepository extends Repository<Prekey, Long> {
    Prekey save(Prekey prekey);
    List<Prekey> saveAll(Iterable<Prekey> prekeys);
    Optional<List<Prekey>> findAllByPerson(Person person);
    void delete(Prekey prekey);
}
