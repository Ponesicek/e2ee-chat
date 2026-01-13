package com.e2echat.app

import android.util.Log
import io.reactivex.android.schedulers.AndroidSchedulers
import io.reactivex.disposables.CompositeDisposable
import io.reactivex.schedulers.Schedulers
import ua.naiksoftware.stomp.Stomp
import ua.naiksoftware.stomp.StompClient
import ua.naiksoftware.stomp.dto.LifecycleEvent

class StompService(
    private val baseUrl: String
) {
    private var stompClient: StompClient? = null
    private val compositeDisposable = CompositeDisposable()
    
    private var onConnected: (() -> Unit)? = null
    private var onError: ((Throwable) -> Unit)? = null
    private var onClosed: (() -> Unit)? = null

    fun connect(
        onConnected: () -> Unit = {},
        onError: (Throwable) -> Unit = {},
        onClosed: () -> Unit = {}
    ) {
        this.onConnected = onConnected
        this.onError = onError
        this.onClosed = onClosed
        
        val wsUrl = baseUrl.replace("https://", "wss://").replace("http://", "ws://")
        val endpoint = "${wsUrl}gs-guide-websocket"
        
        stompClient = Stomp.over(Stomp.ConnectionProvider.OKHTTP, endpoint)
        
        val lifecycleDisposable = stompClient!!.lifecycle()
            .subscribeOn(Schedulers.io())
            .observeOn(AndroidSchedulers.mainThread())
            .subscribe { event ->
                when (event.type) {
                    LifecycleEvent.Type.OPENED -> {
                        Log.d(TAG, "STOMP connection opened")
                        onConnected()
                    }
                    LifecycleEvent.Type.ERROR -> {
                        Log.e(TAG, "STOMP error", event.exception)
                        onError(event.exception ?: Exception("Unknown STOMP error"))
                    }
                    LifecycleEvent.Type.CLOSED -> {
                        Log.d(TAG, "STOMP connection closed")
                        onClosed()
                    }
                    LifecycleEvent.Type.FAILED_SERVER_HEARTBEAT -> {
                        Log.w(TAG, "STOMP server heartbeat failed")
                    }
                    null -> {}
                }
            }
        compositeDisposable.add(lifecycleDisposable)
        
        stompClient!!.connect()
    }

    fun subscribe(
        destination: String,
        onMessage: (String) -> Unit
    ) {
        val client = stompClient ?: run {
            Log.e(TAG, "STOMP client not connected")
            return
        }
        
        val disposable = client.topic(destination)
            .subscribeOn(Schedulers.io())
            .observeOn(AndroidSchedulers.mainThread())
            .subscribe({ message ->
                Log.d(TAG, "Received on $destination: ${message.payload}")
                onMessage(message.payload)
            }, { error ->
                Log.e(TAG, "Error on topic $destination", error)
            })
        compositeDisposable.add(disposable)
    }

    fun send(destination: String, payload: String) {
        val client = stompClient ?: run {
            Log.e(TAG, "STOMP client not connected")
            return
        }
        
        val disposable = client.send(destination, payload)
            .subscribeOn(Schedulers.io())
            .observeOn(AndroidSchedulers.mainThread())
            .subscribe({
                Log.d(TAG, "Sent to $destination: $payload")
            }, { error ->
                Log.e(TAG, "Error sending to $destination", error)
            })
        compositeDisposable.add(disposable)
    }

    fun isConnected(): Boolean = stompClient?.isConnected == true

    fun disconnect() {
        stompClient?.disconnect()
        compositeDisposable.clear()
        stompClient = null
    }

    companion object {
        private const val TAG = "StompService"
    }
}
