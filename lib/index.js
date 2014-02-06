var crypto = require('crypto');
var async = require('async');

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

var extractData = function(rawData) {
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

var encrypt = function(data, password, done) {
	var cipher = crypto.createCipher(ALGORITHM, password);

	console.log(data);
	console.log(password);

	cipher.end(data, 'hex', function() {
		done(null, cipher.read().toString('hex'));
	});
};

var decrypt = function(data, password, done) {
	var decipher = crypto.createDecipher(ALGORITHM, password);

	console.log(data);
	console.log(password);

	decipher.end(data, 'hex', function() {
		//TODO: For some reason this read() call returns null
		done(null, decipher.read().toString('hex'));
	});
};

module.exports = function(schema, options) {
	var properties = options.properties;
	var passwordLookup = options.password;

	//Encrypt the properties before saving to the DB.
	var preSave = function(nextMiddleware) {
		var model = this;

		//Make sure our date instance represents full seconds, not fractions.
		var unix = Math.round(Date.now() / 1000);
		var now = new Date(unix);

		//Encrypt all properties in parallel.
		async.each(properties, function(prop, nextEach) {
			var rawValue = model[prop];

			//Nothing to do here.
			if(!rawValue) {
				return nextEach();
			}

			var salt = createSalt();

			async.waterfall([
				//Look up the password for encryption.
				function(callbackWaterfall) {
					passwordLookup(now, callbackWaterfall);
				},
				//Encrypt the data using the password and salt.
				function(password, callbackWaterfall) {
					var saltedPassword = password + salt;

					encrypt(rawValue, saltedPassword, callbackWaterfall);
				},
				//Store the encrypted data.
				function(encryptedValue, callbackWaterfall) {
					//Compose the value we store.
					var value = MAGIC_PREFIX + createHexTimestamp(unix) + salt + encryptedValue;

					//Here we actually update the model data to the encrypted value.
					model[prop] = value;

					callbackWaterfall();
				}
			], nextEach);
		}, nextMiddleware);
	};

	//Decrypt the properties before the model is instantiated.
	var preInit = function(nextMiddleware, data) {
		//Decrypt all properties in parallel.
		async.each(properties, function(prop, nextEach) {
			var value = data[prop];

			//Nothing to do here.
			if(!value) {
				return nextEach();
			}

			//Nothing to do here, because the value is not encrypted.
			if(!CHECK_MAGIC_PREFIX.test(value)) {
				return nextEach();
			}

			async.waterfall([
				//Look up the password.
				function(callbackWaterfall) {
					var date = extractDate(value);

					passwordLookup(date, callbackWaterfall);
				},
				//Decrypt the value.
				function(password, callbackWaterfall) {
					var salt = extractSalt(value);
					var encryptedValue = extractData(value);
					var saltedPassword = password + salt;

					decrypt(encryptedValue, saltedPassword, callbackWaterfall);
				},
				//Update the model data with the decrypted value.
				function(rawValue, callbackWaterfall) {
					//Here we actually update the model data to the decrypted value.
					data[prop] = rawValue;

					callbackWaterfall();
				}
			], nextEach);
		}, nextMiddleware);
	};

	schema.pre('save', preSave);
	schema.pre('init', preInit);
};