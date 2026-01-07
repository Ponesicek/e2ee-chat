package com.e2echat.backend.database;

import jakarta.persistence.*;

import java.util.List;

@Entity
public class Person {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    private String username;
    private String publicKey;

    public Person(String username, String publicKey) {
        this.username = username;
        this.publicKey = publicKey;
    }

    protected Person() {}

    public String getUsername() {
        return username;
    }

    public String getPublicKey() {
        return publicKey;
    }
}

