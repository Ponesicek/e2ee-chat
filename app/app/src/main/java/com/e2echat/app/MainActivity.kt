package com.e2echat.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.unit.dp
import androidx.lifecycle.lifecycleScope
import com.e2echat.app.ui.contacts.Contact
import com.e2echat.app.ui.theme.AppTheme
import com.google.crypto.tink.config.TinkConfig
import com.google.gson.GsonBuilder
import com.google.gson.Strictness
import kotlinx.coroutines.launch
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory

class MainActivity : ComponentActivity() {
    @OptIn(ExperimentalMaterial3Api::class)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        TinkConfig.register()
        val gson = GsonBuilder()
            .setStrictness(Strictness.LENIENT)
            .create()

        val retrofit = Retrofit.Builder()
            .baseUrl("https://hackclub.ponesicek.com/")
            .addConverterFactory(GsonConverterFactory.create(gson))
            .build()

        val apiService = retrofit.create(ApiService::class.java)
        val cryptoService = CryptoService()
        val authService = AuthService(apiService, cryptoService)
        enableEdgeToEdge()
        setContent {
            var isRegistered by remember { mutableStateOf(false) }
            LaunchedEffect(Unit) {
                if (cryptoService.loadKeyPair() != null) {
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
                        FloatingActionButton(onClick = { }) {
                            Icon(Icons.Default.Add, contentDescription = "Add")
                        }
                    },
                      modifier = Modifier.fillMaxSize(),
                    ) {innerPadding ->
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(innerPadding),
                        verticalArrangement = Arrangement.Center,
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        if (!isRegistered)
                            register(authService) { isRegistered = true }
                        else {
                            val scrollState = rememberScrollState()
                            Column(
                                verticalArrangement = Arrangement.spacedBy(8.dp),
                                modifier = Modifier.verticalScroll(scrollState)
                            ) {
                            Contact("Alice", "How are you doing?")
                            Contact("Bob", "Are you okay?")
                            Contact("John", "That's cool")
                            Contact("Anna", "LMAO!!!")
                            Contact("Peter", "When did that happen?")
                            Contact("Alice", "How are you doing?")
                            Contact("Bob", "Are you okay?")
                            Contact("John", "That's cool")
                            Contact("Anna", "LMAO!!!")
                            Contact("Peter", "When did that happen?")
                            Contact("Alice", "How are you doing?")
                            Contact("Bob", "Are you okay?")
                            Contact("John", "That's cool")
                            Contact("Anna", "LMAO!!!")
                            Contact("Peter", "When did that happen?")
                            }
                        }
                    }
                }
            }
        }
    }

    @Composable
    fun register(authService: AuthService, onRegistered: () -> Unit) {
        var username by remember { mutableStateOf("") }
        var error by remember { mutableStateOf<Exception?>(null) }
        Text(
            text = "Welcome to E2EE Chat!",
        )
        TextField(
            value = username,
            onValueChange = { username = it },
            label = { Text("Username") }
        )
        error?.let { err ->
            val message = if (err.message?.contains("502") == true) {
                "Username already exists"
            } else {
                "Error: ${err.message}"
            }
            Text(text = message, color = androidx.compose.material3.MaterialTheme.colorScheme.error)
        }
        Button(onClick = {
            lifecycleScope.launch {
                var registerOutput = authService.register(username);
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
    fun Contact(name: String, lastMessage: String){
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
                    Text(name)
                    Text(lastMessage)
                }
                Icon(
                    imageVector = Icons.AutoMirrored.Filled.KeyboardArrowRight,
                    contentDescription = "Go to chat"
                )
            }
        }
    }
}
