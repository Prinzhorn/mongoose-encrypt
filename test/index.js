var assert = require('assert');
var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var encrypt = require('../lib');

mongoose.connect('mongodb://localhost/mongoose-encrypt');
mongoose.set('debug', false);

var userSchema = new Schema({
	_id: String,
	secret1: String,
	nested: {
		secret2: String
	}
});

//We'll later adjust this date to simulate password migration.
var newPasswordDate = new Date(2070, 01, 01);

userSchema.plugin(encrypt, {
	paths: ['secret1', 'nested.secret2'],
	password: function(date) {
		if(date >= newPasswordDate) {
			return 'correcthorsebatterystaple';
		} else {
			return 'keyboardkitten';
		}
	}
});

var User = mongoose.model('User', userSchema);

describe('Paths which are not of type String', function() {
	it('should throw an error', function(done) {
		assert.throws(function() {
			(new Schema({
				not_a_string: Number
			})).plugin(encrypt, {
				paths: 'not_a_string',
				password: Math.random()
			});
		});

		done();
	});
});

describe('Basic encryption', function() {
	before(function(done) {
		//Clear the DB.
		User.remove({}, done);
	});

	it('should successfully save a model', function(done) {
		var user = new User({
			_id: 'user1',
			secret1: 'secret'
		});

		user.save(done);
	});

	it('should return an encrypted value when bypassing the plugin by using lean()', function(done) {
		User.findOne({_id: 'user1'}).lean().exec(function(err, user) {
			assert.ifError(err);

			assert.notEqual(user.secret1, 'secret', 'The secret1 is not in plain text.');
			assert(/^ENCRYPTED___/.test(user.secret1), 'The secret1 starts with the magic prefix.');

			assert.strictEqual(user.nested, undefined, 'The nested.secret2 is not set.');

			done();
		});
	});

	it('should decrypt the value when using Mongoose as usual', function(done) {
		User.findOne({_id: 'user1'}).exec(function(err, user) {
			assert.ifError(err);

			assert.strictEqual(user.secret1, 'secret', 'The secret1 is readable.');
			assert.strictEqual(user.nested.secret2, undefined, 'The nested.secret2 is not set.');

			done();
		});
	});

	it('should handle value updates by encrypting the new value', function(done) {
		User.findOne({_id: 'user1'}).exec(function(err, user) {
			assert.ifError(err);

			user.secret1 = 'new secret';
			user.nested.secret2 = 'new secret 2';

			user.save(function(err) {
				assert.ifError(err);

				User.findOne({_id: 'user1'}).exec(function(err, user) {
					assert.ifError(err);

					assert.strictEqual(user.secret1, 'new secret', 'The secret1 has been updated.');
					assert.strictEqual(user.nested.secret2, 'new secret 2', 'The nested.secret2 has been updated.');

					done();
				});
			});
		});
	});

	it('should not double encrypt a value that is already encrypted', function(done) {
		// Encrypted value can get passed around accidentally if it's nested
		var user2 = new User({
			_id: 'user2',
			nested: {
				secret2: 'new secret 2'
			}
		});
		User.findOne({_id: 'user1'}).exec(function(err, user) {
			assert.ifError(err);

			user.nested = user2.nested;

			user.save(function(err) {
				assert.ifError(err);

				User.findOne({_id: 'user1'}).exec(function(err, user) {
					assert.ifError(err);
					assert.strictEqual(user.nested.secret2, 'new secret 2', 'The nested.secret2 has been updated.');
					done();
				});
			});
		});
	});

	it('should leave unset properties untouched', function(done) {
		//Only fetch the _id property.
		User.findOne({_id: 'user1'}, {_id: 1}).exec(function(err, user) {
			assert.ifError(err);

			assert.strictEqual(user.secret1, undefined, 'The secret1 is not set.');
			assert.strictEqual(user.nested.secret2, undefined, 'The nested.secret2 is not set.');

			done();
		});
	});
});

describe('Legacy data, which is already present and unencrypted', function() {
	before(function(done) {
		var user = {
			_id: 'user2',
			secret1: 'secret'
		};

		//Save a user to the DB, but bypass Mongoose.
		User.collection.insert(user, done);
	});

	it('should return the unencrypted value when bypassing the plugin by using lean()', function(done) {
		User.findOne({_id: 'user2'}).lean().exec(function(err, user) {
			assert.ifError(err);

			assert.strictEqual(user.secret1, 'secret', 'The secret1 is readable in plain text.');
			assert.strictEqual(user.nested, undefined, 'The nested.secret2 is not set.');

			done();
		});
	});

	it('should not try to decrypt the legacy data and just return it', function(done) {
		User.findOne({_id: 'user2'}).exec(function(err, user) {
			assert.ifError(err);

			assert.strictEqual(user.secret1, 'secret', 'The secret1 is readable in plain text.');
			assert.strictEqual(user.nested.secret2, undefined, 'The nested.secret2 is not set.');

			done();
		});
	});

	it('should encrypt the data when saving the model back to the DB using Mongoose', function(done) {
		User.findOne({_id: 'user2'}).exec(function(err, user) {
			assert.ifError(err);

			user.secret1 = user.secret1;

			user.save(function(err) {
				assert.ifError(err);

				User.findOne({_id: 'user2'}).lean().exec(function(err, user) {
					assert.ifError(err);

					assert.notEqual(user.secret1, 'secret', 'The secret1 is not in plain text.');
					assert(/^ENCRYPTED___/.test(user.secret1), 'The secret1 starts with the magic prefix.');

					done();
				});
			});
		});
	});
});

describe('Password migration', function() {
	before(function(done) {
		newPasswordDate = new Date();

		//Wait a moment to make sure the password migration actually has to different dates to use.
		setTimeout(done, 10);
	});

	it('should use the old password for decryption and then the new one for encryption', function(done) {
		User.findOne({_id: 'user2'}).lean().exec(function(err, user) {
			assert.ifError(err);

			var oldEncryptedValue = user.secret1;
			assert.notEqual(user.secret1, 'secret', 'The secret1 is not in plain text.');

			User.findOne({_id: 'user2'}).exec(function(err, user) {
				assert.ifError(err);

				assert.strictEqual(user.secret1, 'secret', 'The secret1 is readable.');

				user.secret1 = user.secret1;

				user.save(function(err, user) {
					assert.ifError(err);

					//TODO: this one is failing, because when encrypting the data in `pre save` hook,
					//they are also encrypted when using this instance after saving.
					assert.strictEqual(user.secret1, 'secret', 'The secret1 is readable.');

					User.findOne({_id: 'user2'}).lean().exec(function(err, user) {
						assert.ifError(err);

						assert.notEqual(user.secret1, 'secret', 'The secret1 is not in plain text.');
						assert.notEqual(user.secret1, oldEncryptedValue, 'The two encrypted values differ.');

						done();
					});
				});
			});
		});
	});
});