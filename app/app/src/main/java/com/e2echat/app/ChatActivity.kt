package com.e2echat.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.remember
import com.e2echat.app.ui.chat.ChatMessage
import com.e2echat.app.ui.chat.ChatScreen
import com.e2echat.app.ui.theme.AppTheme
import java.util.UUID

class ChatActivity : ComponentActivity() {
    companion object {
        const val EXTRA_CONTACT_ID = "contact_id"
        const val EXTRA_CONTACT_NAME = "contact_name"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        val contactId = intent.getStringExtra(EXTRA_CONTACT_ID) ?: ""
        val contactName = intent.getStringExtra(EXTRA_CONTACT_NAME) ?: "Unknown"
        
        enableEdgeToEdge()
        setContent {
            val chatMessages = remember { mutableStateListOf<ChatMessage>() }
            
            AppTheme {
                ChatScreen(
                    contactName = contactName,
                    messages = chatMessages,
                    onSendMessage = { messageText ->
                        val newMessage = ChatMessage(
                            id = UUID.randomUUID().toString(),
                            content = messageText,
                            isFromMe = true
                        )
                        chatMessages.add(newMessage)
                    },
                    onBack = { finish() }
                )
            }
        }
    }
}
