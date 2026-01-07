package com.e2echat.backend.database;

import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.Repository;

import java.util.List;
import java.util.Optional;

interface MessageRepository extends CrudRepository<Message, Long> {
    Message save(Message message);
}
