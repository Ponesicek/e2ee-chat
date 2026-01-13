package com.e2echat.app.ui.contacts

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken

class ContactsRepository(context: Context) {
    
    private val prefs: SharedPreferences = 
        context.getSharedPreferences("contacts", Context.MODE_PRIVATE)
    private val gson = Gson()

    fun getContacts(): List<Contact> {
        val json = prefs.getString(CONTACTS_KEY, null) ?: return emptyList()
        val type = object : TypeToken<List<Contact>>() {}.type
        return gson.fromJson(json, type)
    }

    fun addContact(contact: Contact) {
        val contacts = getContacts().toMutableList()
        if (contacts.none { it.name == contact.name }) {
            contacts.add(contact)
            saveContacts(contacts)
        }
    }

    fun removeContact(name: String) {
        val contacts = getContacts().toMutableList()
        contacts.removeAll { it.name == name }
        saveContacts(contacts)
    }

    fun updateContact(contact: Contact) {
        val contacts = getContacts().toMutableList()
        val index = contacts.indexOfFirst { it.id == contact.id }
        if (index >= 0) {
            contacts[index] = contact
            saveContacts(contacts)
        }
    }

    fun getContactById(id: String): Contact? {
        return getContacts().find { it.id == id }
    }

    private fun saveContacts(contacts: List<Contact>) {
        val json = gson.toJson(contacts)
        prefs.edit { putString(CONTACTS_KEY, json) }
    }

    companion object {
        private const val CONTACTS_KEY = "contacts_list"
    }
}
