package com.e2echat.backend.database;

import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

import java.util.List;

@RedisHash("Session")
public class Message {
    @Id
    private Long reciever;
    private List<MessageEntry> entries;
}