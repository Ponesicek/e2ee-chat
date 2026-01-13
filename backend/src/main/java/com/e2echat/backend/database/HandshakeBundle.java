package com.e2echat.backend.database;

import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.index.Indexed;

@RedisHash("HandshakeBundle")
public class HandshakeBundle {
    @Id
    private String id;
    
    @Indexed
    private String recipientUsername;
    
    private String senderUsername;
    private String ephemeralKey;
    private String identityKey;
    private String usedOneTimePreKeyId;
    private long createdAt;
    
    public HandshakeBundle() {}
    
    public HandshakeBundle(String recipientUsername, String senderUsername, String ephemeralKey, 
                          String identityKey, String usedOneTimePreKeyId) {
        this.recipientUsername = recipientUsername;
        this.senderUsername = senderUsername;
        this.ephemeralKey = ephemeralKey;
        this.identityKey = identityKey;
        this.usedOneTimePreKeyId = usedOneTimePreKeyId;
        this.createdAt = System.currentTimeMillis();
    }
    
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    
    public String getRecipientUsername() { return recipientUsername; }
    public void setRecipientUsername(String recipientUsername) { this.recipientUsername = recipientUsername; }
    
    public String getSenderUsername() { return senderUsername; }
    public void setSenderUsername(String senderUsername) { this.senderUsername = senderUsername; }
    
    public String getEphemeralKey() { return ephemeralKey; }
    public void setEphemeralKey(String ephemeralKey) { this.ephemeralKey = ephemeralKey; }
    
    public String getIdentityKey() { return identityKey; }
    public void setIdentityKey(String identityKey) { this.identityKey = identityKey; }
    
    public String getUsedOneTimePreKeyId() { return usedOneTimePreKeyId; }
    public void setUsedOneTimePreKeyId(String usedOneTimePreKeyId) { this.usedOneTimePreKeyId = usedOneTimePreKeyId; }
    
    public long getCreatedAt() { return createdAt; }
    public void setCreatedAt(long createdAt) { this.createdAt = createdAt; }
}
