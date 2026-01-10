package com.e2echat.backend.database;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;

@Entity
public class Prekey {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @ManyToOne
    private Person person;
    private int prekeyId;
    @Column(length = 2048)
    private String prekey;

    public Prekey(Person person, int prekeyId, String prekey) {
        this.person = person;
        this.prekeyId = prekeyId;
        this.prekey = prekey;
    }

    public Prekey() {
    }

    public Long getId() {
        return id;
    }

    public Person getPerson() {
        return person;
    }

    public int getPrekeyId() {
        return prekeyId;
    }

    public String getPrekey() {
        return prekey;
    }
}
