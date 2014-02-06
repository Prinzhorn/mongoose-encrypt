mongoose-encrypt
================

Transparent encryption for Mongoose fields with built-in password migration.

Allows you to easily encrypt `String` fields using `aes-256-cbc`.


Idea
====

Store a timestamp along the encrypted data to allow painless encryption key migration.

The data that is stored in MongoDB as UTF-8 strings and consists of (from left to right)

* the string `ENCRYPTED___` to handle a mix of encrypted/unencrypted data (you can drop this plugin into your existing data),
* 8 chars representing the seconds since the Unix epoch in hex (for range query pleasure),
* a 16 char (8 byte) salt string which is randomly generated for every encrypted string and appended to the password,
* and the encrypted data itself as UTF-8 string.


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
	properties: ['twitterToken'],
	password: function(date, done) {
		//Return the correct password for the given date.
		//As long as you don't need to migrate to a new password, just return the current one.
		done(null, process.env.AES_ENCRYPTION_PASSWORD);
	}
});
```

That's it! The plugin sets up pre `init` and `save` hooks to anynchronously decrypt and encrypt each property on the fly using `aes-256-cbc`.


Use cases
=========

As mentioned above storing OAuth tokens or similar in plain text is probably a bad idea. Additional this plugin was created to securely store bank account data on behalf of users.


Heads up
========

I'm not a security expert. Not at all. If you have any concerns regarding this plugin please create an issue (or contact me via e-mail if it's a critical issue).

Also:

* It's a good idea to not store or hardcode the encryption key (the example uses an environment variable)
* This plugin will only secure your data in case someone gets access directly to your database (physically or otherwise)
* You still need to make sure the data is transmitted securely (e.g. using TLS)
* If someone gets access to your application server (not just the database), you're screwed anyway