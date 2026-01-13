package com.e2echat.backend.database;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface HandshakeBundleRepository extends CrudRepository<HandshakeBundle, String> {
    List<HandshakeBundle> findAllByRecipientUsername(String recipientUsername);
    Optional<HandshakeBundle> findByRecipientUsernameAndSenderUsername(String recipientUsername, String senderUsername);
}
