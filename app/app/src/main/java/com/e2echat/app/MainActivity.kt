package com.e2echat.app

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
        val authService = AuthService(apiService, cryptoService)
        val contactsRepository = ContactsRepository(applicationContext)
        
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
                            ContactsScreen(contacts)
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
                                    contactsRepository.addContact(newContact)
                                    contacts = contactsRepository.getContacts()
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
    fun ContactsScreen(contacts: List<Contact>) {
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
                    ContactItem(contact.name, contact.lastMessage)
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
    fun ContactItem(name: String, lastMessage: String) {
        Card(
            Modifier
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
                    Text(name, style = MaterialTheme.typography.titleMedium)
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
