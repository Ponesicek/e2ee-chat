package com.e2echat.backend.database;

import jakarta.persistence.*;
import org.springframework.data.redis.core.RedisHash;

import java.util.List;

@RedisHash("Session")
public class Message {
    @Id
    private String reciever;
    private List<MessageEntry> entries;
}