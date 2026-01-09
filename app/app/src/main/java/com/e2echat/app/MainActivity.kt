package com.e2echat.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.lifecycle.lifecycleScope
import com.e2echat.app.ui.theme.AppTheme
import com.google.crypto.tink.config.TinkConfig
import com.google.gson.GsonBuilder
import kotlinx.coroutines.launch
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        TinkConfig.register();
        val gson = GsonBuilder()
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
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(innerPadding),
                        verticalArrangement = Arrangement.Center,
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {

                        if (!isRegistered)
                            register(authService, cryptoService) { isRegistered = true }
                        else
                            Text(text = "You are logged in!")
                    }
                }
            }

        }
    }

    @Composable
    fun register(authService: AuthService, cryptoService: CryptoService, onRegistered: () -> Unit) {
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
                }
                else {
                    onRegistered()
                }
            }
        }) {
            Text("Register")
        }

    }
}
