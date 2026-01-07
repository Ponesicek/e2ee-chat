package com.e2echat.backend;

import jakarta.persistence.*;

@Entity
class Message {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @ManyToOne
    private Person sender;

    @ManyToOne
    private Person receiver;

    private String messageForSender;
    private String messageForReciever;

    public Message(Person sender, Person receiver, String messageForSender, String messageForReciever) {
        this.sender = sender;
        this.receiver = receiver;
        this.messageForSender = messageForSender;
        this.messageForReciever = messageForReciever;
    }

    protected Message() {}

    public Person getSender() {
        return sender;
    }

    public Person getReceiver() {
        return receiver;
    }

    public String getMessageForSender() {
        return messageForSender;
    }

    public String getMessageForReciever() {
        return messageForReciever;
    }
}

