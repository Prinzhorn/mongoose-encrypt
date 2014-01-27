var crypto = require('crypto');

var MAGIC_PREFIX = 'Encrypted___';
var ALGORITHM = 'aes256';
var IV_LENGTH = 16;

var encrypt = function(data, key, iv) {
	var cipher = crypto.createCipheriv(ALGORITHM, key, iv);

	var buf1 = cipher.update(data, 'utf8');
	var buf2 = cipher.final();

	return Buffer.concat([buf1, buf2]).toString('utf8');
};

var decrypt = function(data, key, iv) {
	var decipher = crypto.createDecipheriv(ALGORITHM, key, iv);

	var buf1 = decipher.update(data, 'utf8');
	var buf2 = decipher.final();

	return Buffer.concat([buf1, buf2]).toString('utf8');
};

module.exports = function(schema, options) {
	options.fields.forEach(function(field) {
		schema.path(field).get(function(value) {


			var hexTimestamp = value.substr(0, 8);
			var timestamp = parseInt(hexTimestamp, 16);
			var date = new Date(timestamp * 1000);

			var key = new Buffer(options.key(date), 'utf8');

			var iv = new Buffer(value.substr(8, 40), 'hex');

			return decrypt(value, key, iv);
		});

		schema.path(field).set(function(value) {
			var now = new Date();
			var timestamp = Math.round(now.getTime() / 1000);
			var hexTimestamp = ('00000000' + timestamp.toString(16)).substr(-8);

			var key = new Buffer(options.key(now), 'utf8');

			//For our case `pseudoRandomBytes()` is enough compared to `randomBytes()`.
			var iv = crypto.pseudoRandomBytes(16);

			return hexTimestamp + iv.toString('hex') + encrypt(value, key, iv);
		});
	});
};