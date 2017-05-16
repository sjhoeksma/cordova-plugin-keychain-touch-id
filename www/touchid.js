var argscheck = require('cordova/argscheck'),
               exec = require('cordova/exec');

var touchid = {
	isAvailable: function(successCallback, errorCallback){
		exec(successCallback, errorCallback, "TouchID", "isAvailable", []);
	},
	saveKey: function(key,password, successCallback, errorCallback) {
		exec(successCallback, errorCallback, "TouchID", "save", [key,password]);
	},
	verifyKey: function(key,message,successCallback, errorCallback){
		exec(successCallback, errorCallback, "TouchID", "verify", [key,message]);
	},
	hasKey: function(key,successCallback, errorCallback){
		exec(successCallback, errorCallback, "TouchID", "has", [key]);
	},
	deleteKey: function(key,successCallback, errorCallback){
		exec(successCallback, errorCallback, "TouchID", "delete", [key]);
	},
	setLocale: function(locale,successCallback, errorCallback){
		exec(successCallback, errorCallback, "TouchID", "setLocale", [locale]);
	},
	didFingerprintDatabaseChange: function (successCallback, errorCallback) {
		exec(successCallback, errorCallback, "TouchID", "didFingerprintDatabaseChange", []);
	}
};

module.exports = touchid;
