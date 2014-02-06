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

userSchema.plugin(encrypt, {
	properties: ['secret1', 'secret2'],
	password: function(date, done) {
		done(null, 'keyboardkitten');
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

	after(function(done) {
		//Clear the DB.
		User.remove({}, done);
	});
});