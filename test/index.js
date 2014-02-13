var assert = require('assert');
var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var encrypt = require('../lib');

mongoose.connect('mongodb://localhost/mongoose-encrypt');
mongoose.set('debug', true);

var userSchema = new Schema({
	_id: String,
	secret1: String,
	secret2: String
});

var useNewPassword = false;

userSchema.plugin(encrypt, {
	properties: ['secret1', 'secret2'],
	password: function(date, done) {
		//The "useNewPassword" flag is only used for the unit tests.
		//In a real world scenario you would return the password depending on the date parameter.
		//E.g. when you want to use the new password starting on 01.01.2014,
		//then return the new one for all dates greater than this and the old password otherwise.

		done(null, useNewPassword ? 'correcthorsebatterystaple' : 'keyboardkitten');
	}
});

var User = mongoose.model('User', userSchema);

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

			assert.strictEqual(user.secret2, undefined, 'The secret2 is not set.');

			done();
		});
	});

	it('should decrypt the value when using Mongoose as usual', function(done) {
		User.findOne({_id: 'user1'}).exec(function(err, user) {
			assert.ifError(err);

			assert.strictEqual(user.secret1, 'secret', 'The secret1 is readable.');
			assert.strictEqual(user.secret2, undefined, 'The secret2 is not set.');

			done();
		});
	});

	it('should handle value updates by encrypting the new value', function(done) {
		User.findOne({_id: 'user1'}).exec(function(err, user) {
			assert.ifError(err);

			user.secret1 = 'new secret';
			user.secret2 = 'new secret 2';

			user.save(function(err) {
				assert.ifError(err);

				User.findOne({_id: 'user1'}).exec(function(err, user) {
					assert.ifError(err);

					assert.strictEqual(user.secret1, 'new secret', 'The secret1 has been updated.');
					assert.strictEqual(user.secret2, 'new secret 2', 'The secret2 has been updated.');

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
			assert.strictEqual(user.secret2, undefined, 'The secret2 is not set.');

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
			assert.strictEqual(user.secret2, undefined, 'The secret2 is not set.');

			done();
		});
	});

	it('should not try to decrypt the legacy data and just return it', function(done) {
		User.findOne({_id: 'user2'}).exec(function(err, user) {
			assert.ifError(err);

			assert.strictEqual(user.secret1, 'secret', 'The secret1 is readable in plain text.');
			assert.strictEqual(user.secret2, undefined, 'The secret2 is not set.');

			done();
		});
	});

	it('should encrypt the data when saving the model back to the DB using Mongoose', function(done) {
		User.findOne({_id: 'user2'}).exec(function(err, user) {
			assert.ifError(err);

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
	it('should use the old password for decryption and then the new one for encryption', function(done) {
		User.findOne({_id: 'user2'}).lean().exec(function(err, user) {
			assert.ifError(err);

			var oldEncryptedValue = user.secret1;
			assert.notEqual(user.secret1, 'secret', 'The secret1 is not in plain text.');

			User.findOne({_id: 'user2'}).exec(function(err, user) {
				assert.ifError(err);

				assert.strictEqual(user.secret1, 'secret', 'The secret1 is readable.');
				useNewPassword = true;

				user.save(function(err, user) {
					assert.ifError(err);

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