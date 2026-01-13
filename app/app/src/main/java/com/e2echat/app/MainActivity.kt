package com.e2echat.app

import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.lifecycleScope
import com.e2echat.app.ui.contacts.Contact
import com.e2echat.app.ui.contacts.ContactsRepository
import com.e2echat.app.ui.theme.AppTheme
import com.google.gson.GsonBuilder
import com.google.gson.Strictness
import com.google.gson.reflect.TypeToken
import kotlinx.coroutines.launch
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory

class MainActivity : ComponentActivity() {
    @OptIn(ExperimentalMaterial3Api::class)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val gson = GsonBuilder()
            .setStrictness(Strictness.LENIENT)
            .create()

        val retrofit = Retrofit.Builder()
            .baseUrl("https://hackclub.ponesicek.com/")
            .addConverterFactory(GsonConverterFactory.create(gson))
            .build()

        val apiService = retrofit.create(ApiService::class.java)
        val cryptoService = CryptoService(applicationContext)
        val authService = AuthService(applicationContext, apiService, cryptoService)
        val contactsRepository = ContactsRepository(applicationContext)
        val stompService = StompService("https://hackclub.ponesicek.com/")
        
        enableEdgeToEdge()
        setContent {
            var isRegistered by remember { mutableStateOf(false) }
            var contacts by remember { mutableStateOf(contactsRepository.getContacts()) }
            var showAddContactDialog by remember { mutableStateOf(false) }
            
            LaunchedEffect(Unit) {
                if (cryptoService.getIdentityPublicKey() != null) {
                    isRegistered = true
                }
            }
            
            DisposableEffect(isRegistered) {
                if (isRegistered) {
                    stompService.connect(
                        onConnected = {
                            val username = authService.getUsername()
                            if (username != null) {
                                stompService.subscribe("/app/topic/messages.$username") { message ->
                                    android.util.Log.d("STOMP", "Received message: $message")
                                    lifecycleScope.launch {
                                        processIncomingHandshakes(message, gson, cryptoService, contactsRepository) {
                                            contacts = contactsRepository.getContacts()
                                        }
                                    }
                                }
                            }
                        },
                        onError = { error ->
                            android.util.Log.e("STOMP", "Connection error", error)
                        }
                    )
                }
                onDispose {
                    stompService.disconnect()
                }
            }
            
            AppTheme {
                Scaffold(
                    topBar = {
                        TopAppBar(
                            title = { Text("Opaque") }
                        )
                    },
                    floatingActionButton = {
                        if (isRegistered) {
                            FloatingActionButton(onClick = { showAddContactDialog = true }) {
                                Icon(Icons.Default.Add, contentDescription = "Add Contact")
                            }
                        }
                    },
                    modifier = Modifier.fillMaxSize(),
                ) { innerPadding ->
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(innerPadding),
                        verticalArrangement = Arrangement.Center,
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        if (!isRegistered) {
                            RegisterScreen(authService) { isRegistered = true }
                        } else {
                            ContactsScreen(contacts) { contact ->
                                if (contact.hasSession) {
                                    openChat(contact)
                                } else {
                                    lifecycleScope.launch {
                                        if (contact.identityKey == null || contact.signedPreKey == null || contact.signedPreKeySignature == null) {
                                            Toast.makeText(
                                                this@MainActivity,
                                                "Missing keys for ${contact.name}",
                                                Toast.LENGTH_SHORT
                                            ).show()
                                            return@launch
                                        }
                                        
                                        val result = cryptoService.performX3DHHandshake(
                                            theirIdentityKey = contact.identityKey,
                                            theirSignedPreKey = contact.signedPreKey,
                                            theirSignedPreKeySignature = contact.signedPreKeySignature,
                                            theirOneTimePreKey = contact.oneTimePreKey,
                                        )
                                        
                                        result.onSuccess { x3dhResult ->
                                            cryptoService.storeSession(
                                                contactId = contact.id,
                                                sharedSecret = x3dhResult.sharedSecret,
                                                ephemeralPublicKey = x3dhResult.ephemeralPublicKey
                                            )
                                            
                                            val myUsername = authService.getUsername()
                                            val myIdentityKey = cryptoService.getIdentityPublicKey()
                                            if (myUsername != null && myIdentityKey != null) {
                                                val handshakeBundle = ApiService.HandshakeBundleRequest(
                                                    recipientUsername = contact.name,
                                                    senderUsername = myUsername,
                                                    ephemeralKey = x3dhResult.ephemeralPublicKey,
                                                    identityKey = myIdentityKey,
                                                    usedOneTimePreKeyId = contact.preKeyId
                                                )
                                                apiService.submitHandshake(handshakeBundle)
                                            }
                                            
                                            contactsRepository.updateContact(contact.copy(hasSession = true))
                                            contacts = contactsRepository.getContacts()
                                            openChat(contact.copy(hasSession = true))
                                        }.onFailure { error ->
                                            val message = when (error) {
                                                is X3DHError.InvalidSignature -> "Invalid signature from ${contact.name}"
                                                is X3DHError.MissingKeys -> "Missing keys"
                                                else -> "Handshake failed: ${error.message}"
                                            }
                                            Toast.makeText(
                                                this@MainActivity,
                                                message,
                                                Toast.LENGTH_SHORT
                                            ).show()
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                
                if (showAddContactDialog) {
                    AddContactDialog(
                        onDismiss = { showAddContactDialog = false },
                        onAddContact = { name ->
                            lifecycleScope.launch {
                                val response = apiService.getKeys(name)
                                if (response.isSuccessful && response.body() != null) {
                                    val keys = response.body()!!
                                    val newContact = Contact(
                                        name = name,
                                        identityKey = keys.IdentityKey,
                                        signedPreKey = keys.SignedPreKey,
                                        signedPreKeySignature = keys.SignedPreKeySignature,
                                        oneTimePreKey = keys.OneTimePreKey,
                                        preKeyId = keys.PreKeyID
                                    )
                                    
                                    val handshakeResult = cryptoService.performX3DHHandshake(
                                        theirIdentityKey = keys.IdentityKey,
                                        theirSignedPreKey = keys.SignedPreKey,
                                        theirSignedPreKeySignature = keys.SignedPreKeySignature,
                                        theirOneTimePreKey = keys.OneTimePreKey,
                                    )
                                    
                                    handshakeResult.onSuccess { x3dhResult ->
                                        cryptoService.storeSession(
                                            contactId = newContact.id,
                                            sharedSecret = x3dhResult.sharedSecret,
                                            ephemeralPublicKey = x3dhResult.ephemeralPublicKey
                                        )
                                        
                                        val myUsername = authService.getUsername()
                                        val myIdentityKey = cryptoService.getIdentityPublicKey()
                                        if (myUsername != null && myIdentityKey != null) {
                                            val handshakeBundle = ApiService.HandshakeBundleRequest(
                                                recipientUsername = name,
                                                senderUsername = myUsername,
                                                ephemeralKey = x3dhResult.ephemeralPublicKey,
                                                identityKey = myIdentityKey,
                                                usedOneTimePreKeyId = keys.PreKeyID
                                            )
                                            apiService.submitHandshake(handshakeBundle)
                                        }
                                        
                                        contactsRepository.addContact(newContact.copy(hasSession = true))
                                        contacts = contactsRepository.getContacts()
                                        Toast.makeText(
                                            this@MainActivity,
                                            "Added ${name} with secure session",
                                            Toast.LENGTH_SHORT
                                        ).show()
                                    }.onFailure { error ->
                                        val message = when (error) {
                                            is X3DHError.InvalidSignature -> "Invalid signature from ${name}"
                                            else -> "Handshake failed: ${error.message}"
                                        }
                                        Toast.makeText(
                                            this@MainActivity,
                                            message,
                                            Toast.LENGTH_SHORT
                                        ).show()
                                    }
                                }
                                else {
                                    Toast.makeText(
                                        this@MainActivity,
                                        "Error: ${response.code()}",
                                        Toast.LENGTH_SHORT
                                    ).show()
                                }
                                showAddContactDialog = false
                            }
                        }
                    )
                }
            }
        }
    }
    
    private fun openChat(contact: Contact) {
        val intent = Intent(this, ChatActivity::class.java).apply {
            putExtra(ChatActivity.EXTRA_CONTACT_ID, contact.id)
            putExtra(ChatActivity.EXTRA_CONTACT_NAME, contact.name)
        }
        startActivity(intent)
    }

    private suspend fun processIncomingHandshakes(
        message: String,
        gson: com.google.gson.Gson,
        cryptoService: CryptoService,
        contactsRepository: ContactsRepository,
        onContactsUpdated: () -> Unit
    ) {
        try {
            val type = object : TypeToken<List<ApiService.HandshakeBundleResponse>>() {}.type
            val handshakes: List<ApiService.HandshakeBundleResponse> = gson.fromJson(message, type)

            for (handshake in handshakes) {
                val existingContact = contactsRepository.getContacts().find { it.name == handshake.senderUsername }
                if (existingContact?.hasSession == true) {
                    android.util.Log.d("X3DH", "Session already exists for ${handshake.senderUsername}")
                    continue
                }

                val result = cryptoService.respondToX3DH(
                    theirIdentityKey = handshake.identityKey,
                    theirEphemeralKey = handshake.ephemeralKey,
                    usedOneTimePreKeyId = handshake.usedOneTimePreKeyId
                )

                result.onSuccess { x3dhResult ->
                    val contact = existingContact?.copy(
                        identityKey = handshake.identityKey,
                        hasSession = true
                    ) ?: Contact(
                        name = handshake.senderUsername,
                        identityKey = handshake.identityKey,
                        hasSession = true
                    )

                    cryptoService.storeSession(
                        contactId = contact.id,
                        sharedSecret = x3dhResult.sharedSecret,
                        ephemeralPublicKey = x3dhResult.ephemeralPublicKey
                    )

                    if (existingContact != null) {
                        contactsRepository.updateContact(contact)
                    } else {
                        contactsRepository.addContact(contact)
                    }

                    android.util.Log.d("X3DH", "Session established with ${handshake.senderUsername}")
                    runOnUiThread { onContactsUpdated() }
                }.onFailure { error ->
                    android.util.Log.e("X3DH", "Failed to process handshake from ${handshake.senderUsername}: ${error.message}")
                }
            }
        } catch (e: Exception) {
            android.util.Log.e("X3DH", "Failed to parse handshakes: ${e.message}")
        }
    }

    @Composable
    fun RegisterScreen(authService: AuthService, onRegistered: () -> Unit) {
        var username by remember { mutableStateOf("") }
        var error by remember { mutableStateOf<Exception?>(null) }
        
        Text(
            text = "Welcome to E2EE Chat!",
            style = MaterialTheme.typography.headlineMedium
        )
        
        OutlinedTextField(
            value = username,
            onValueChange = { username = it },
            label = { Text("Username") },
            modifier = Modifier.padding(vertical = 16.dp)
        )
        
        error?.let { err ->
            val message = if (err.message?.contains("502") == true) {
                "Username already exists"
            } else {
                "Error: ${err.message}"
            }
            Text(
                text = message,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.padding(bottom = 8.dp)
            )
        }
        
        Button(onClick = {
            lifecycleScope.launch {
                val registerOutput = authService.register(username)
                if (registerOutput != null) {
                    error = registerOutput
                } else {
                    onRegistered()
                }
            }
        }) {
            Text("Register")
        }
    }

    @Composable
    fun ContactsScreen(
        contacts: List<Contact>,
        onContactClick: (Contact) -> Unit
    ) {
        if (contacts.isEmpty()) {
            Text(
                text = "No contacts yet.\nTap + to add a contact.",
                style = MaterialTheme.typography.bodyLarge,
                modifier = Modifier.padding(16.dp)
            )
        } else {
            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.fillMaxSize()
            ) {
                items(contacts) { contact ->
                    ContactItem(
                        name = contact.name,
                        lastMessage = contact.lastMessage,
                        hasSession = contact.hasSession,
                        onClick = { onContactClick(contact) }
                    )
                }
            }
        }
    }

    @Composable
    fun AddContactDialog(onDismiss: () -> Unit, onAddContact: (String) -> Unit) {
        var name by remember { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = onDismiss,
            title = { Text("Add Contact") },
            text = {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Name") },
                    singleLine = true
                )
            },
            confirmButton = {
                TextButton(
                    onClick = { if (name.isNotBlank()) onAddContact(name.trim()) },
                    enabled = name.isNotBlank()
                ) {
                    Text("Add")
                }
            },
            dismissButton = {
                TextButton(onClick = onDismiss) {
                    Text("Cancel")
                }
            }
        )
    }

    @Composable
    fun ContactItem(
        name: String, 
        lastMessage: String,
        hasSession: Boolean,
        onClick: () -> Unit
    ) {
        Card(
            onClick = onClick,
            modifier = Modifier
                .fillMaxWidth()
                .height(80.dp)
                .padding(horizontal = 8.dp)
        ) {
            Row(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 16.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(name, style = MaterialTheme.typography.titleMedium)
                        if (hasSession) {
                            Text(
                                " 🔐",
                                style = MaterialTheme.typography.bodySmall
                            )
                        }
                    }
                    if (lastMessage.isNotEmpty()) {
                        Text(
                            lastMessage,
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
                Icon(
                    imageVector = Icons.AutoMirrored.Filled.KeyboardArrowRight,
                    contentDescription = "Go to chat"
                )
            }
        }
    }
}
