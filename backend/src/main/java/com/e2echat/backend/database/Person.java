package com.e2echat.backend.database;

import jakarta.persistence.*;

@Entity
public class Person {

    public Long getId() {
        return id;
    }

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    private String username;
    private String masterPublicKey;
    @Column(length = 2048)
    private String signedPreKey;
    @Column(length = 2048)
    private String signedPreKeySignature;

    public Person(String username, String masterPublicKey, String signedPreKey, String signedPreKeySignature) {
        this.username = username;
        this.masterPublicKey = masterPublicKey;
        this.signedPreKey = signedPreKey;
        this.signedPreKeySignature = signedPreKeySignature;
    }

    protected Person() {}

    public String getUsername() {
        return username;
    }
    public String getMasterPublicKey() {
        return masterPublicKey;
    }
    public String getSignedPreKey() {
        return signedPreKey;
    }
    public String getSignedPreKeySignature() {
        return signedPreKeySignature;
    }
}

