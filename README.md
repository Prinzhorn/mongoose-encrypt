mongoose-encrypt
================

Transparent encryption for Mongoose fields with encryption key migration built in.

Allows you to easily encrypt `String` fields using `aes256`.


Idea
====

Store a timestamp along the encrypted data to allow painless encryption key migration.

The data that is stored in MongoDB as UTF-8 strings and consists of (from left to right)

* a 4-byte value representing the seconds since the Unix epoch,
* a 16-byte value representing the initialization vector,
* arbitrary the encrypted data

This allows us to query for data that has been encrypted before/after a certain time (e.g. for migration purposes).


Usage
=====

First `npm install mongoose-encrypt`.

Now imagine a website where users sign up with their Twitter account. It's probably a good idea to encrypt the OAuth token.

```js
var encrypt = require('mongoose-encrypt');

var userSchema = new Schema({
	name: String,
	twitterToken: String
});

offerSchema.plugin(encrypt, {
	fields: ['twitterToken'],
	key: function(date) {
		//Return the correct key for the given date.
		//As long as you don't need to migrate to a new key, just return the current one.
		return process.env.AES_DB_KEY;
	}
});
```

That's it! The plugin creates `get`ter and `set`ter for each field and transparently encrypts it on the fly using `aes256`.


Use cases
=========

As mentioned above storing OAuth tokens or similar in plain text is probably a bad idea. Additional this plugin was created to securely store bank account data on behalf of users.


Heads up
========

I'm no a security expert. Not at all. If you have any concerns regarding this plugin please create an issue.

Also:

* It's a good idea to not store or hardcode the encryption key (the example uses an environment variable)
* This plugin will only secure your data in case someone gets access directly to your database (physically or otherwise)
* You still need to make sure the data is transmitted securely (e.g. using TLS)
* If someone gets access to your application server (not just the database), you're screwed anyway