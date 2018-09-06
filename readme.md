# cordova-plugin-keychain-touch-id

A cordova plugin adding the iOS TouchID or FaceID / Android fingerprint to your app and allowing you to store a password securely in the device keychain.

## Based on the original Touch ID created by different people

* https://github.com/EddyVerbruggen/cordova-plugin-touch-id
* https://github.com/kunder-lab/kunder-touchid-keychain
* https://github.com/PeerioTechnologies/peerio-keychain-touchid
* https://github.com/nheezemans/touchid/blob/master/src/ios/TouchID.m

Cordova plugin for interacting with iOS touchId and keychain

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

`touchid.js` is brought in automatically. There is no need to change or add anything in your html.

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

## Usage

Call the function you like:

* `touchid.isAvailable([successCallback(biometryType), errorCallback(msg)])` function checks if `touchid` is available on the used device. The `successCallback` gets the `biometryType` argument with 'face' on iPhone X, 'touch' on other devices.

* `touchid.save(key, password, [userAuthenticationRequired, successCallback(), errorCallback(msg))]` function saves a `password` indexed by a `key` in the device keychain. If `userAuthenticationRequired` param is `true` (default value), then the user will be asked to authenticate before saving the password to give the app more security. Otherwise there's no need to authenticate to save.

* `touchid.verify(key, [message, successCallback(password), errorCallback(errorCode)])` function opens the fingerprint dialog, for the given `key`, showing an additional message. `successCallback` will return the password stored in the device keychain. `errorCallback` will return an error code, where -1 indicates that the `key` is not available.

* `touchid.has(key, [successCallback(), errorCallback()])` function checks if there is a `password` stored in the device keychain for the given `key`.

* `delete(key, [successCallback(), errorCallback()])` function deletes the `password` stored under given `key` in the device keychain.

## Android quirks

When a new fingerprint is enrolled, no more fingerprints are enrolled, secure lock screen is disabled or forcibly reset,
the key which is used to hash the password is permanently invalidated. It cannot be used anymore.

`verify` and `save` functions will return the `"KeyPermanentlyInvalidatedException"` message in the error callback. This invalid key is removed - user needs to **save their password again**.

## Examples

Make sure the plugins are enabled before all.

```js
if (!window.plugins || !window.plugins.touchid) {
    alert('Plugins are not available')
}
```

**Scenario 1**: Check if a password has already been saved under the key `MyKey`.

```js
window.plugins.touchid.isAvailable(
    biometryType => {
        const serviceName = biometryType === 'face' ? 'Face ID' : 'Touch ID';

        window.plugins.touchid.has(
            'MyKey',
            () => {
                // Success
                alert(
                    serviceName +
                        'service is available, and password for key "MyKey" is registered'
                );
            },
            () => {
                // Failure
                alert(
                    serviceName +
                        'service is available, but Password for key "MyKey" is not registered'
                );
            }
        );
    },
    () => {
        alert('Biometry (Touch or Face ID) is not available');
    }
);
```

**Scenario 2**: Store your credentials after entering username/password. Recover them next time you reopen the app.

``` js
document.getElementById('form-login').addEventListener('submit', event => {
    event.preventDefault();

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    const credentials = JSON.stringify({ username, password });

    window.plugins.touchid.isAvailable(() => {
        window.plugins.touchid.save('MyKey', credentials, true, () => {
            alert(`Credentials saved`);
        });
    });
});

document.addEventListener(
    'deviceready',
    () => {
        window.plugins.touchid.isAvailable(() => {
            window.plugins.touchid.verify(
                'MyKey',
                'Recover your credentials from the keychain',
                savedCredentials => {
                    const { login, password } = JSON.parse(savedCredentials);

                    alert(`Your credentials are ${login}:${password}`);
                }
            );
        });
    },
    false
);
```
