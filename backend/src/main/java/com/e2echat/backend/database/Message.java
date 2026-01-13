package com.e2echat.backend.database;

import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.index.Indexed;

import java.util.List;

@RedisHash("Session")
public class Message {
    @Id
    private String id;

    @Indexed
    private Long reciever;
    private List<MessageEntry> entries;
}