var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var encrypt = require('../lib');

mongoose.connect('mongodb://localhost/mongoose-encrypt');
mongoose.set('debug', true);

var userSchema = new Schema({
	name: String,
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

User.remove({}, function(err) {
	if(err) {
		console.error(err);
	}

	var user = new User({
		name: 'Alexander',
		secret1: 'secret'
	});

	user.save(function(err) {
		if(err) {
			console.error(err);
		}

		User.findOne().exec(function(err, user) {
			console.log(user.secret1);
		});
	});
});