

# cordova-plugin-keychain-touch-id 

A cordova plugin adding the iOS TouchID / Android fingerprint to your app and allowing you to store a password securely in the device keychain.

## Installation

### Automatically (CLI / Plugman)
Compatible with [Cordova Plugman](https://github.com/apache/cordova-plugman), compatible with [PhoneGap 3.0 CLI](http://docs.phonegap.com/en/3.0.0/guide_cli_index.md.html#The%20Command-line%20Interface_add_features), here's how it works with the CLI (backup your project first!):

From npm:
```
$ cordova plugin add cordova-plugin-keychain-touch-id
$ cordova prepare
```

The latest, from the master repo:
```
$ cordova plugin add https://github.com/sjhoeksma/cordova-plugin-keychain-touch-id
$ cordova prepare
```

touchid.js is brought in automatically. There is no need to change or add anything in your html.

### Manually

1\. Add the following xml to your `config.xml` in the root directory of your `www` folder:
```xml
<feature name="TouchID">
  <param name="ios-package" value="TouchID" />
</feature>
```

You'll need to add the `LocalAuthentication.framework` and `Security.framework` to your project.
Click your project, Build Phases, Link Binary With Libraries, search for and add the frameworks.

2\. Grab a copy of TouchID.js, add it to your project and reference it in `index.html`:
```html
<script type="text/javascript" src="js/touchid.js"></script>
```

3\. Download the source files and copy them to your project.

iOS: Copy the four `.h` and two `.m` files to `platforms/ios/<ProjectName>/Plugins`

### Base on the original touch ID created by different people
* https://github.com/sjhoeksma/cordova-plugin-keychain-touch-id
* https://github.com/EddyVerbruggen/cordova-plugin-touch-id
* https://github.com/kunder-lab/kunder-touchid-keychain
* https://github.com/PeerioTechnologies/peerio-keychain-touchid
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
	
**saveKey(key,password, successCallback, errorCallback(msg))**
will save a password under the key in the device keychain, which can be retrieved using a fingerprint

**verifyKey(key,message,successCallback(password), errorCallback(errorCode))**
will open the fingerprint dialog, for the given key, showing an additional message.
successCallback will return the password stored in key chain.
errorCallback will return the error code, where -1 indicated not available.

**hasKey(key,successCallback, errorCallback)**
will check if there is a password stored within the keychain for the given key

**deleteKey(key,successCallback, errorCallback)**
will delete the password stored under given key from the keychain

**didFingerprintDatabaseChange(successCallback, errorCallback)**
IOS ONLY! checks fingerprint database and returns whether it has been modified or not


## Security++
Since iOS9 it's possible to check whether or not the list of enrolled fingerprints changed since
the last time you checked it. It's recommended you add this check so you can counter hacker attacks
to your app. See [this article](https://godpraksis.no/2016/03/fingerprint-trojan/) for more details.

So instead of checking the fingerprint after `isAvailable` add another check.
In case `didFingerprintDatabaseChange` returns `true` you probably want to re-authenticate your user
before accepting valid fingerprints again.

## Android quirks

When a new fingerprint is enrolled, no more fingerprints are enrolled, secure lock screen is disabled or forcibly reset,
the key which is used to hash the password is permanently invalidated. It cannot be used anymore.

`verifyKey` and `saveKey` functions will return the `"KeyPermanentlyInvalidatedException"` message in the error callback.
This invalid key is removed - user needs to **save their password again**.

# Examples

```js
if (window.plugins) {
    window.plugins.touchid.isAvailable(function() {
        window.plugins.touchid.hasKey("MyKey", function() {
            alert("Touch ID avaialble and Password key available");
        }, function() {
            alert("Touch ID available but no Password Key available");
        });
    }, function(msg) {
        alert("no Touch ID available");
    });
}

if (window.plugins) {
    window.plugins.touchid.verifyKey("MyKey", "My Message", function(password) {
        alert("Tocuh " + password);
    });
}

if (window.plugins) {
    window.plugins.touchid.saveKey("MyKey", "My Password", function() {
        alert("Password saved");
    });
}

if (window.plugins) {
    window.plugins.touchid.deleteKey("MyKey", function() {
        alert("Password key deleted");
    });
}
```

