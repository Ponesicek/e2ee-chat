package com.e2echat.backend.database;

import java.io.Serializable;
import java.time.LocalDateTime;

public class MessageEntry implements Serializable {
    private Long senderId;
    private String content;

    public MessageEntry(Long senderId, String content) {
        this.senderId = senderId;
        this.content = content;
    }

    public Long getSenderId() {
        return senderId;
    }

    public String getContent() {
        return content;
    }
}
