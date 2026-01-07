package com.e2echat.backend.database;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericToStringSerializer;
import org.springframework.data.redis.serializer.JacksonJsonRedisSerializer;

import java.util.List;

@Configuration
public class RedisConfig {

    @Bean
    public RedisTemplate<Long, List<MessageEntry>> redisTemplate(RedisConnectionFactory connectionFactory) {
        RedisTemplate<Long, List<MessageEntry>> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);

        // Use JSON for the values (the list of objects)
        JacksonJsonRedisSerializer<Object> serializer = new JacksonJsonRedisSerializer<>(Object.class);

        template.setKeySerializer(new GenericToStringSerializer<>(Long.class));
        template.setValueSerializer(serializer);
        return template;
    }
}
