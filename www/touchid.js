var argscheck = require('cordova/argscheck'),
               exec = require('cordova/exec');
               
var touchID = {
	isAvailable: function(successCallback, errorCallback){
		exec(successCallback, errorCallback, "TouchID", "isTouchIDAvailable", []);
	},
	save: function(key,password, successCallback, errorCallback) {
		exec(successCallback, errorCallback, "TouchID", "savePasswordToKeychain", [key,password]);
	},
	verify: function(key,message,successCallback, errorCallback){
		exec(successCallback, errorCallback, "TouchID", "getPasswordFromKeychain", [key,message]);
	},
	has: function(key,successCallback, errorCallback){
		exec(successCallback, errorCallback, "TouchID", "hasPasswordInKeychain", [key]);
	},
	delete: function(key,successCallback, errorCallback){
		exec(successCallback, errorCallback, "TouchID", "deleteKeychainPassword", [key]);
	}
};

module.exports = touchID;