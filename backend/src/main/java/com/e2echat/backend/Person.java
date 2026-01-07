package com.e2echat.backend;

import jakarta.persistence.*;

import java.util.List;

@Entity
class Person {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    private String username;
    private String passwordHash;
    private String publicKey;

    @ManyToMany
    private List<Person> friends;

    public Person(String username, String password, String publicKey) {
        this.username = username;
        this.passwordHash = password;
        this.publicKey = publicKey;
    }

    protected Person() {}

    public String getUsername() {
        return username;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public List<Person> getFriends() {
        return friends;
    }

    public void addFriend(Person friend) {
        this.friends.add(friend);
    }


}

