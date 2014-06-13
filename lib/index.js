var crypto = require('crypto');

var MAGIC_PREFIX = 'ENCRYPTED___';//Aww Yiss, more underscores.
var CHECK_MAGIC_PREFIX = new RegExp('^' + MAGIC_PREFIX);
var ALGORITHM = 'aes-256-cbc';
var SALT_BYTE_LENGTH = 16;

//As a reminder, this is how we store the data (pipes not actually included).
//ENCRYPTED___|timestamp|salt|data

//The magic prefix begins at position 0 (duh).
var OFFSET_MAGIC_PREFIX = 0;
var LENGTH_MAGIC_PREFIX = MAGIC_PREFIX.length;

//The timestamp comes right after the magic prefix.
var OFFSET_TIMESTAMP = OFFSET_MAGIC_PREFIX + LENGTH_MAGIC_PREFIX;
var LENGTH_TIMESTAMP = 8;//4 bytes in hex characters.

//The salt comes right after the timestamp.
var OFFSET_SALT = OFFSET_TIMESTAMP + LENGTH_TIMESTAMP;
var LENGTH_SALT = SALT_BYTE_LENGTH * 2;//#hex = 2 * #bytes

//The data comes right after the timestamp and ends at the very end of the string.
var OFFSET_DATA = OFFSET_SALT + LENGTH_SALT;

var extractDate = function(rawData) {
	var hexTimestamp = rawData.substr(OFFSET_TIMESTAMP, LENGTH_TIMESTAMP);
	var timestamp = parseInt(hexTimestamp, 16);
	var date = new Date(timestamp * 1000);

	return hexTimestamp;
};

var extractSalt = function(rawData) {
	return rawData.substr(OFFSET_SALT, LENGTH_SALT);
};

var extractValue = function(rawData) {
	return rawData.substr(OFFSET_DATA);
};

var createHexTimestamp = function(unix) {
	//Left pad the hex timestamp with zeros.
	var hexTimestamp = ('00000000' + unix.toString(16)).substr(-8);

	return hexTimestamp;
};

var createSalt = function() {
	var salt = crypto.pseudoRandomBytes(SALT_BYTE_LENGTH).toString('hex');

	return salt;
};

var encrypt = function(data, password) {
	var cipher = crypto.createCipher(ALGORITHM, password);
	var encrypted = cipher.update(data, 'utf8', 'base64') + cipher.final('base64');

	return encrypted;
};

var decrypt = function(data, password) {
	var decipher = crypto.createDecipher(ALGORITHM, password);
	var decrypted = decipher.update(data, 'base64', 'utf8') + decipher.final('utf8');

	return decrypted;
};

module.exports = function(schema, options) {
	var paths = options.paths;
	var getPassword = options.password;

	var setter = function(rawValue) {
		if(!rawValue) {
			return rawValue;
		}

		if(CHECK_MAGIC_PREFIX.test(rawValue)) {
			return rawValue;
		}

		var unix = Math.round(Date.now() / 1000);
		var now = new Date(unix);

		//Create a random salt.
		var salt = createSalt();

		//Get the password for the current date and time.
		var password = getPassword(now);

		var saltedPassword = password + salt;
		var encryptedValue = encrypt(rawValue, saltedPassword);

		//Compose the value we store.
		var value = MAGIC_PREFIX + createHexTimestamp(unix) + salt + encryptedValue;

		return value;
	};

	var getter = function(value) {
		if(!value) {
			return value;
		}

		//Nothing to do here, because the value is not encrypted.
		if(!CHECK_MAGIC_PREFIX.test(value)) {
			return value;
		}

		//Extract all the things that are encoded in the stored value.
		var date = extractDate(value);
		var password = getPassword(date);
		var salt = extractSalt(value);
		var encryptedValue = extractValue(value);

		var saltedPassword = password + salt;

		var rawValue = decrypt(encryptedValue, saltedPassword);

		return rawValue;
	};

	paths.forEach(function(path) {
		var pathMeta = schema.paths[path];

		//Make sure the path is of type String.
		if(!pathMeta || pathMeta.options.type !== String) {
			throw new Error('mongoose-encrypt can only be used on String properties. Was applied to "' + path + '" which is of type "' + pathMeta.options.type.name + '".');
		}

		schema.path(path).set(setter);
		schema.path(path).get(getter);
	});
};