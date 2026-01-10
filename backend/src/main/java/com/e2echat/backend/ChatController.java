package com.e2echat.backend;

import com.e2echat.backend.database.Person;
import com.e2echat.backend.database.PersonRepository;
import com.e2echat.backend.database.Prekey;
import com.e2echat.backend.database.PrekeyRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Optional;

@RestController
public class ChatController {
    private final PersonRepository personRepository;
    private final PrekeyRepository prekeyRepository;
    public ChatController(PersonRepository personRepository, PrekeyRepository prekeyRepository) {
        this.personRepository = personRepository;
        this.prekeyRepository = prekeyRepository;
    }

    public record KeysResponse(String IdentityKey, String SignedPreKey, String SignedPreKeySignature, String OneTimePreKey, String PreKeyID) {}

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
}
