package com.e2echat.backend;

import com.e2echat.backend.database.Person;
import com.e2echat.backend.database.PersonRepository;
import com.e2echat.backend.database.Prekey;
import com.e2echat.backend.database.PrekeyRepository;
import com.e2echat.backend.database.HandshakeBundle;
import com.e2echat.backend.database.HandshakeBundleRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.messaging.handler.annotation.DestinationVariable;
import org.springframework.messaging.simp.annotation.SubscribeMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Optional;

@RestController
public class ChatController {
    private final PersonRepository personRepository;
    private final PrekeyRepository prekeyRepository;
    private final HandshakeBundleRepository handshakeBundleRepository;
    
    public ChatController(PersonRepository personRepository, PrekeyRepository prekeyRepository, 
                         HandshakeBundleRepository handshakeBundleRepository) {
        this.personRepository = personRepository;
        this.prekeyRepository = prekeyRepository;
        this.handshakeBundleRepository = handshakeBundleRepository;
    }

    public record KeysResponse(String IdentityKey, String SignedPreKey, String SignedPreKeySignature, String OneTimePreKey, String PreKeyID) {}

    public record HandshakeBundleRequest(String recipientUsername, String senderUsername, 
                                         String ephemeralKey, String identityKey, String usedOneTimePreKeyId) {}

    public record HandshakeBundleResponse(String senderUsername, String ephemeralKey, 
                                          String identityKey, String usedOneTimePreKeyId) {}

    @PostMapping("/handshake")
    public ResponseEntity<String> submitHandshake(@RequestBody HandshakeBundleRequest request) {
        if (request.recipientUsername == null || request.senderUsername == null || 
            request.ephemeralKey == null || request.identityKey == null) {
            return ResponseEntity.badRequest().body("Missing required fields");
        }
        
        HandshakeBundle bundle = new HandshakeBundle(
            request.recipientUsername,
            request.senderUsername,
            request.ephemeralKey,
            request.identityKey,
            request.usedOneTimePreKeyId
        );
        handshakeBundleRepository.save(bundle);
        return ResponseEntity.status(HttpStatus.CREATED).body("OK");
    }

    @GetMapping("/handshake")
    public ResponseEntity<List<HandshakeBundleResponse>> getPendingHandshakes(@RequestParam String username) {
        List<HandshakeBundle> bundles = handshakeBundleRepository.findAllByRecipientUsername(username);
        List<HandshakeBundleResponse> responses = bundles.stream()
            .map(b -> new HandshakeBundleResponse(b.getSenderUsername(), b.getEphemeralKey(), 
                                                   b.getIdentityKey(), b.getUsedOneTimePreKeyId()))
            .toList();
        bundles.forEach(handshakeBundleRepository::delete);
        return ResponseEntity.ok(responses);
    }

    /**
     * Provides endpoint to retrieve user cryptographic keys
     */
    @GetMapping("/getkeys")
    public ResponseEntity<KeysResponse> getKeys(@RequestParam String username) {
        Optional<Person> maybePerson = personRepository.findByUsername(username);
        if(maybePerson.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        Person person = maybePerson.get();
        Optional<List<Prekey>> maybePrekeys = prekeyRepository.findAllByPerson(person);
        if(maybePrekeys.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        List<Prekey> prekeys = maybePrekeys.get();
        if(prekeys.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        Prekey prekey = prekeys.removeFirst();
        prekeyRepository.delete(prekey);
        return ResponseEntity.ok(new KeysResponse(person.getMasterPublicKey(), person.getSignedPreKey(), person.getSignedPreKeySignature(), prekey.getPrekey(), prekey.getPrekeyId()+""));
    }

    @SubscribeMapping("/topic/messages.{username}")
    public List<HandshakeBundleResponse> pullHandshakesAndMessages(@DestinationVariable String username) {
        System.out.println("Pulling handshakes for " + username);
        List<HandshakeBundle> bundles = handshakeBundleRepository.findAllByRecipientUsername(username);
        List<HandshakeBundleResponse> responses = bundles.stream()
                .map(b -> new HandshakeBundleResponse(b.getSenderUsername(), b.getEphemeralKey(),
                        b.getIdentityKey(), b.getUsedOneTimePreKeyId()))
                .toList();
        bundles.forEach(handshakeBundleRepository::delete);
        return responses;
    }

}
