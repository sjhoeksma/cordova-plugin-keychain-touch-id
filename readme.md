# touchId & keychain cordova plugin

Base on the original touch ID created by different people
* https://github.com/kunder-lab/kunder-touchid-keychain
* https://github.com/PeerioTechnologies/peerio-keychain-touchid,
* https://github.com/nheezemans/touchid/blob/master/src/ios/TouchID.m

Cordova plugin for interacting with iOS touchId and keychain

# Usage

Make sure you check if the plugin is installed 

```
if (window.plugins.touchid) {

}
```

Call the function you like

**isAvailable(successCallback, errorCallback(msg))** will Check if touchid is available on the used device 	
	
**save(key,password, successCallback, errorCallback(msg))** 
will save a password under the key in the device keychain, which can be retrieved using a fingerprint

**verify(key,message,successCallback(password), errorCallback(errorCode))**
wil open the fingerprint dialog, for the given key, showing an additional message.
successCallback will return the password stored in key chain.
errorCallback will return the error code, where -1 indicated not avaialbe.

**has(key,successCallback, errorCallback)**
will check if there is a password stored within the keychain for the given key

**delete(key,successCallback, errorCallback)**
will delete the password stored under given key from the keychain


# Examples

```
	if (window.plugins.touchid) {
		window.plugins.touchid.isAvailable(function(){
			 window.plugins.touchid.has("MyKey",function(){
				 alert("Touch ID avaialble and Password key avaialble");
			 },function(){
			   alert("Touch ID available but no Password Key available");
		},function(msg){
			alert("no Touch ID available");
		});
	}
	
	if (window.plugins.touchid) {
		  window.plugins.touchid.verify("MyKey","My Message",function(password){
			  alert("Tocuh " + password);
		  });
	}
	
	if (window.plugins.touchid) {
		  window.plugins.touchid.save("MyKey","My Password",function(){
			   alert("Password saved");
      });
  }
	
  if (window.plugins.touchid) {
		  window.plugins.touchid.delete("MyKey",function(){
			   alert("Password key deleted");
      });
  }			
```

