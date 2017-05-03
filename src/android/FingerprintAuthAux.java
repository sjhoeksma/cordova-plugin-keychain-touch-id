package com.cordova.plugin.android.fingerprintauth;

/**
 * Created by manuelmouta on 24/02/2017.
 */

import android.Manifest;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.DisplayMetrics;
import android.util.Log;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Locale;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;


public class FingerprintAuthAux {

    public static final String TAG = "FingerprintAuth";
    private static final String DIALOG_FRAGMENT_TAG = "FpAuthDialog";
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String SHARED_PREFS_NAME = "FingerSPref";

    // Plugin response codes and messages
    private static final String OS = "OS";
    private static final String ANDROID = "Android";
    private static final String ERROR_CODE = "ErrorCode";
    private static final String ERROR_MESSAGE = "ErrorMessage";
    private static final String NO_SECRET_KEY_CODE = "-5";
    private static final String NO_SECRET_MESSAGE = "Secret Key not set.";
    private static final String NO_HARDWARE_CODE = "-6";
    private static final String NO_HARDWARE_MESSAGE = "Biometry is not available on this device.";
    private static final String NO_FINGERPRINT_ENROLLED_CODE = "-7";
    private static final String NO_FINGERPRINT_ENROLLED_MESSAGE =
            "No fingers are enrolled with Touch ID.";

    // Plugin Javascript actions
    private static final String SAVE = "save";
    private static final String VERIFY = "verify";
    private static final String IS_AVAILABLE = "isAvailable";
    private static final String SET_LOCALE = "setLocale";
    private static final String HAS = "has";
    private static final String DELETE = "delete";
    private static final String MOVE = "move";

    /**
     * Alias for our key in the Android Key Store
     */
    private final static String CLIENT_ID = "CordovaTouchPlugin";
    public static String packageName;
    public static KeyStore mKeyStore;
    public static KeyGenerator mKeyGenerator;
    public static Cipher mCipher;
    public static CallbackContext mCallbackContext;
    public static PluginResult mPluginResult;
    /**
     * Used to encrypt token
     */
    private static String mKeyID;
    KeyguardManager mKeyguardManager;
    FingerprintAuthenticationDialogFragment mFragment;
    private FingerprintManager mFingerPrintManager;
    private int mCurrentMode;
    private String mLangCode = "en_US";

    private FingerprintAuth mParentCordovaPlugin;
    /**
     * String to encrypt
     */
    private String mToEncrypt;

    /**
     * Require the user to authenticate with a fingerprint to authorize every use of the key
     */
    private boolean setUserAuthenticationRequired = false;

    /**
     * Constructor.
     */
    public FingerprintAuthAux(FingerprintAuth mainCordovaPlugin) {
        mParentCordovaPlugin = mainCordovaPlugin;
    }

    /**
     * Creates a symmetric key in the Android Key Store which can only be used after the user has
     * authenticated with fingerprint.
     */
    public static boolean createKey(final boolean setUserAuthenticationRequired) {
        String errorMessage = "";
        String createKeyExceptionErrorPrefix = "Failed to create key: ";
        boolean isKeyCreated = false;
        // The enrolling flow for fingerprint. This is where you ask the user to set up fingerprint
        // for your flow. Use of keys is necessary if you need to know if the set of
        // enrolled fingerprints has changed.
        try {
            mKeyStore.load(null);
            // Set the alias of the entry in Android KeyStore where the key will appear
            // and the constrains (purposes) in the constructor of the Builder
            mKeyGenerator.init(new KeyGenParameterSpec.Builder(CLIENT_ID,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT).setBlockModes(
                    KeyProperties.BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(setUserAuthenticationRequired)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build());
            mKeyGenerator.generateKey();
            isKeyCreated = true;
        } catch (NoSuchAlgorithmException e) {
            errorMessage = createKeyExceptionErrorPrefix + "NoSuchAlgorithmException";
        } catch (InvalidAlgorithmParameterException e) {
            errorMessage = createKeyExceptionErrorPrefix + "InvalidAlgorithmParameterException";
        } catch (CertificateException e) {
            errorMessage = createKeyExceptionErrorPrefix + "CertificateException";
        } catch (IOException e) {
            errorMessage = createKeyExceptionErrorPrefix + "IOException";
        }
        if (!isKeyCreated) {
            Log.e(TAG, errorMessage);
            setPluginResultError(errorMessage);
        }
        return isKeyCreated;
    }

    public static void onCancelled() {
        mCallbackContext.error("Cancelled");
    }

    public static boolean setPluginResultError(String errorMessage) {
        mCallbackContext.error(errorMessage);
        mPluginResult = new PluginResult(PluginResult.Status.ERROR);
        return false;
    }

    /**
     * Sets the context of the Command. This can then be used to do things like
     * get file paths associated with the Activity.
     *
     * @param cordova The context of the main Activity.
     * @param webView The CordovaWebView Cordova is running in.
     */

    public void initialize(CordovaInterface cordova, CordovaWebView webView) {

        Log.v(TAG, "Init FingerprintAuth");
        packageName = cordova.getActivity().getApplicationContext().getPackageName();
        mPluginResult = new PluginResult(PluginResult.Status.NO_RESULT);

        if (android.os.Build.VERSION.SDK_INT < 23) {
            return;
        }

        mKeyguardManager = cordova.getActivity().getSystemService(KeyguardManager.class);
        mFingerPrintManager =
                cordova.getActivity().getApplicationContext().getSystemService(FingerprintManager.class);

        try {
            mKeyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);
            mKeyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to get an instance of KeyGenerator", e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException("Failed to get an instance of KeyGenerator", e);
        } catch (KeyStoreException e) {
            throw new RuntimeException("Failed to get an instance of KeyStore", e);
        }

        try {
            mCipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES
                    + "/"
                    + KeyProperties.BLOCK_MODE_CBC
                    + "/"
                    + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to get an instance of Cipher", e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException("Failed to get an instance of Cipher", e);
        }
    }

    /**
     * Executes the request and returns PluginResult.
     *
     * @param action The action to execute.
     * @param args JSONArry of arguments for the plugin.
     * @param callbackContext The callback id used when calling back into JavaScript.
     * @return A PluginResult object with a status and message.
     */
    public boolean execute(final String action, JSONArray args, CallbackContext callbackContext, CordovaInterface cordova)
            throws JSONException {
        mCallbackContext = callbackContext;
        Log.v(TAG, "FingerprintAuth action: " + action);
        if (android.os.Build.VERSION.SDK_INT < 23) {
            Log.e(TAG, "minimum SDK version 23 required");

            String errorMessage = createErrorMessage(NO_HARDWARE_CODE, NO_HARDWARE_MESSAGE);
            mPluginResult = new PluginResult(PluginResult.Status.ERROR, errorMessage);
            mCallbackContext.sendPluginResult(mPluginResult);
            return true;
        }
        if (action.equals(SAVE)) {
            final String key = args.getString(0);
            final String password = args.getString(1);
            setUserAuthenticationRequired = args.get(2).equals(null) || args.getBoolean(2);

            if (isFingerprintAuthAvailable()) {
                SecretKey secretKey = getSecretKey();

                if (secretKey == null) {
                    if (createKey(setUserAuthenticationRequired)) {
                        getSecretKey();
                    }
                }
                mKeyID = key;
                mToEncrypt = password;

                if (setUserAuthenticationRequired) {
                    showFingerprintDialog(Cipher.ENCRYPT_MODE, null, cordova);
                } else {
                    SharedPreferences sharedPref = cordova.getActivity().getApplicationContext().getSharedPreferences(SHARED_PREFS_NAME,Context.MODE_PRIVATE);
                    SharedPreferences.Editor editor = sharedPref.edit();

                    if (initCipher(Cipher.ENCRYPT_MODE, cordova)) {
                        byte[] enc = new byte[0];
                        try {
                            enc = mCipher.doFinal(mToEncrypt.getBytes());

                            editor.putString("fing" + mKeyID, Base64.encodeToString(enc, Base64.DEFAULT));
                            editor.putString("fing_iv" + mKeyID,
                                    Base64.encodeToString(mCipher.getIV(), Base64.DEFAULT));

                            editor.apply();
                            mPluginResult = new PluginResult(PluginResult.Status.OK);
                            mCallbackContext.sendPluginResult(mPluginResult);
                            return true;
                        } catch (IllegalBlockSizeException e) {
                            mPluginResult =
                                    new PluginResult(PluginResult.Status.ERROR, "Error string is to big.");
                        } catch (BadPaddingException e) {
                            mPluginResult = new PluginResult(PluginResult.Status.ERROR, "Error Bad Padding.");
                        }
                        mCallbackContext.sendPluginResult(mPluginResult);
                    }
                }
            } else {
                String errorMessage = createErrorMessage(NO_HARDWARE_CODE, NO_HARDWARE_MESSAGE);
                mPluginResult = new PluginResult(PluginResult.Status.ERROR, errorMessage);
            }
            return true;
        } else if (action.equals(VERIFY)) {
            final String key = args.getString(0);
            final String message = args.getString(1);
            if (isHardwareDetected()) {
                if (hasEnrolledFingerprints()) {
                    SecretKey secretKey = getSecretKey();
                    if (secretKey != null) {
                        mKeyID = key;
                        showFingerprintDialog(Cipher.DECRYPT_MODE, message, cordova);
                        mPluginResult.setKeepCallback(true);
                    } else {
                        String errorMessage = createErrorMessage(NO_SECRET_KEY_CODE, NO_SECRET_MESSAGE);
                        mPluginResult = new PluginResult(PluginResult.Status.ERROR, errorMessage);
                        mCallbackContext.sendPluginResult(mPluginResult);
                    }
                } else {
                    String errorMessage =
                            createErrorMessage(NO_FINGERPRINT_ENROLLED_CODE, NO_FINGERPRINT_ENROLLED_MESSAGE);
                    mPluginResult = new PluginResult(PluginResult.Status.ERROR, errorMessage);
                    mCallbackContext.sendPluginResult(mPluginResult);
                }
            } else {
                String errorMessage = createErrorMessage(NO_HARDWARE_CODE, NO_HARDWARE_MESSAGE);
                mPluginResult = new PluginResult(PluginResult.Status.ERROR, errorMessage);
                mCallbackContext.sendPluginResult(mPluginResult);
            }
            return true;
        } else if (action.equals(IS_AVAILABLE)) {
            if (isHardwareDetected()) {
                if (hasEnrolledFingerprints()) {
                    mPluginResult = new PluginResult(PluginResult.Status.OK);
                } else {
                    String errorMessage =
                            createErrorMessage(NO_FINGERPRINT_ENROLLED_CODE, NO_FINGERPRINT_ENROLLED_MESSAGE);
                    mPluginResult = new PluginResult(PluginResult.Status.ERROR, errorMessage);
                }
            } else {
                String errorMessage = createErrorMessage(NO_HARDWARE_CODE, NO_HARDWARE_MESSAGE);
                mPluginResult = new PluginResult(PluginResult.Status.ERROR, errorMessage);
            }

            mCallbackContext.sendPluginResult(mPluginResult);
            return true;
        } else if (action.equals(SET_LOCALE)) {            // Set language
            mLangCode = args.getString(0);
            Resources res = cordova.getActivity().getResources();

            // Change locale settings in the app.
            DisplayMetrics dm = res.getDisplayMetrics();

            Configuration conf = res.getConfiguration();
            conf.locale = new Locale(mLangCode.toLowerCase());

            res.updateConfiguration(conf, dm);
            return true;
        } else if (action.equals(HAS)) { //if has key
            String key = args.getString(0);

            SharedPreferences sharedPref = cordova.getActivity().getApplicationContext().getSharedPreferences(SHARED_PREFS_NAME,Context.MODE_PRIVATE);
            String enc = sharedPref.getString("fing" + key, "");

            if (!enc.equals("")) {
                mPluginResult = new PluginResult(PluginResult.Status.OK);
            } else {
                mPluginResult = new PluginResult(PluginResult.Status.ERROR);
            }

            mCallbackContext.sendPluginResult(mPluginResult);
            return true;
        } else if (action.equals(DELETE)) { //delete key
            final String key = args.getString(0);
            SharedPreferences sharedPref = cordova.getActivity().getApplicationContext().getSharedPreferences(SHARED_PREFS_NAME,Context.MODE_PRIVATE);
            SharedPreferences.Editor editor = sharedPref.edit();
            editor.remove("fing" + key);
            editor.remove("fing_iv" + key);
            boolean removed = editor.commit();
            if (removed) {
                mPluginResult = new PluginResult(PluginResult.Status.OK);
            } else {
                mPluginResult = new PluginResult(PluginResult.Status.ERROR);
            }
            mCallbackContext.sendPluginResult(mPluginResult);
            return true;
        } else if (action.equals(MOVE)) { //Move shared preferences from activity to global
            String key = args.getString(0);
            String oldActivityPackageName = args.getString(1);
            //Get old shared Preferences e.g: "com.outsystems.android.WebApplicationActivity"
            SharedPreferences oldSharedPref = cordova.getActivity().getApplicationContext().getSharedPreferences(oldActivityPackageName,Context.MODE_PRIVATE);
            String enc = oldSharedPref.getString("fing" + key, "");
            
            if (!enc.equals("")) {
                SharedPreferences newSharedPref = cordova.getActivity().getApplicationContext().getSharedPreferences(SHARED_PREFS_NAME,Context.MODE_PRIVATE);
                SharedPreferences.Editor newEditor = newSharedPref.edit();
                newEditor.putString("fing" + key, oldSharedPref.getString("fing" + key, ""));
                newEditor.putString("fing_iv" + key, oldSharedPref.getString("fing_iv" + key, ""));
                newEditor.commit();
                
                SharedPreferences.Editor oldEditor = oldSharedPref.edit();
                oldEditor.remove("fing" + key);
                oldEditor.remove("fing_iv" + key);
                oldEditor.commit();
            }
            
            mPluginResult = new PluginResult(PluginResult.Status.OK);
            mCallbackContext.sendPluginResult(mPluginResult);
            return true;
        }
        return false;
    }

    private boolean isFingerprintAuthAvailable() {
        return isHardwareDetected() && hasEnrolledFingerprints();
    }

    private boolean isHardwareDetected() {
        if (mParentCordovaPlugin == null || mParentCordovaPlugin.cordova.getActivity().checkSelfPermission(Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
            return false;
        }

        return mFingerPrintManager.isHardwareDetected();
    }

    private boolean hasEnrolledFingerprints() {
        if (mParentCordovaPlugin == null || mParentCordovaPlugin.cordova.getActivity().checkSelfPermission(Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
            return false;
        }

        return mFingerPrintManager.hasEnrolledFingerprints();
    }

    /**
     * Initialize the {@link Cipher} instance with the created key in the
     * {@link #createKey(boolean setUserAuthenticationRequired)}
     * method.
     *
     * @return {@code true} if initialization is successful, {@code false} if the lock screen has
     * been disabled or reset after the key was generated, or if a fingerprint got enrolled after
     * the key was generated.
     */
    private boolean initCipher(int mode, CordovaInterface cordova) {
        boolean initCipher = false;
        String errorMessage = "";
        String initCipherExceptionErrorPrefix = "Failed to init Cipher: ";
        try {
            SecretKey key = getSecretKey();

            if (mode == Cipher.ENCRYPT_MODE) {
                SecureRandom r = new SecureRandom();
                byte[] ivBytes = new byte[16];
                r.nextBytes(ivBytes);

                mCipher.init(mode, key);
            } else {
                SharedPreferences sharedPref = cordova.getActivity().getApplicationContext().getSharedPreferences(SHARED_PREFS_NAME,Context.MODE_PRIVATE);
                byte[] ivBytes =
                        Base64.decode(sharedPref.getString("fing_iv" + mKeyID, ""), Base64.DEFAULT);

                mCipher.init(mode, key, new IvParameterSpec(ivBytes));
            }

            initCipher = true;
        } catch (KeyPermanentlyInvalidatedException e) {
            removePermanentlyInvalidatedKey();
            errorMessage = "KeyPermanentlyInvalidatedException";
            setPluginResultError(errorMessage);
        } catch (InvalidKeyException e) {
            errorMessage = initCipherExceptionErrorPrefix + "InvalidKeyException";
        } catch (InvalidAlgorithmParameterException e) {
            errorMessage = initCipherExceptionErrorPrefix + "InvalidAlgorithmParameterException";
            e.printStackTrace();
        }
        if (!initCipher) {
            Log.e(TAG, errorMessage);
        }
        return initCipher;
    }

    private SecretKey getSecretKey() {
        String errorMessage = "";
        String getSecretKeyExceptionErrorPrefix = "Failed to get SecretKey from KeyStore: ";
        SecretKey key = null;
        try {
            mKeyStore.load(null);
            key = (SecretKey) mKeyStore.getKey(CLIENT_ID, null);
        } catch (KeyStoreException e) {
            errorMessage = getSecretKeyExceptionErrorPrefix + "KeyStoreException";
        } catch (CertificateException e) {
            errorMessage = getSecretKeyExceptionErrorPrefix + "CertificateException";
        } catch (UnrecoverableKeyException e) {
            errorMessage = getSecretKeyExceptionErrorPrefix + "UnrecoverableKeyException";
        } catch (IOException e) {
            errorMessage = getSecretKeyExceptionErrorPrefix + "IOException";
        } catch (NoSuchAlgorithmException e) {
            errorMessage = getSecretKeyExceptionErrorPrefix + "NoSuchAlgorithmException";
        } catch (UnrecoverableEntryException e) {
            errorMessage = getSecretKeyExceptionErrorPrefix + "UnrecoverableEntryException";
        }
        if (key == null) {
            Log.e(TAG, errorMessage);
        }
        return key;
    }

    public void showFingerprintDialog(final int mode, final String message, final CordovaInterface cordova) {
        final FingerprintAuthAux auth = this;
        mCurrentMode = mode;
        cordova.getActivity().runOnUiThread(new Runnable() {
            public void run() {
                // Set up the crypto object for later. The object will be authenticated by use
                // of the fingerprint.
                mFragment = new FingerprintAuthenticationDialogFragment();
                Bundle bundle = new Bundle();
                bundle.putInt("dialogMode", mode);
                bundle.putString("dialogMessage", message);
                mFragment.setArguments(bundle);
                mFragment.setmFingerPrintAuth(auth);

                if (initCipher(mode, cordova)) {
                    mFragment.setCancelable(false);
                    // Show the fingerprint dialog. The user has the option to use the fingerprint with
                    // crypto, or you can fall back to using a server-side verified password.
                    mFragment.setCryptoObject(new FingerprintManager.CryptoObject(mCipher));
                    mFragment.show(cordova.getActivity().getFragmentManager(), DIALOG_FRAGMENT_TAG);
                } else {
                    mPluginResult = new PluginResult(PluginResult.Status.ERROR, "Failed to init Cipher");
                    mCallbackContext.sendPluginResult(mPluginResult);
                }
            }
        });
    }

    public void onAuthenticated(boolean withFingerprint) {
        String result = "";
        String errorMessage = "";
        try {

            CordovaInterface cordova = mParentCordovaPlugin.cordova;
            if (withFingerprint) {
                // If the user has authenticated with fingerprint, verify that using cryptography and
                // then return the encrypted token
                SharedPreferences sharedPref = cordova.getActivity().getApplicationContext().getSharedPreferences(SHARED_PREFS_NAME,Context.MODE_PRIVATE);
                if (mCurrentMode == Cipher.DECRYPT_MODE) {
                    byte[] enc = Base64.decode(sharedPref.getString("fing" + mKeyID, ""), Base64.DEFAULT);

                    byte[] decrypted = mCipher.doFinal(enc);
                    result = new String(decrypted);
                } else if (mCurrentMode == Cipher.ENCRYPT_MODE && setUserAuthenticationRequired) {
                    //If setUserAuthenticationRequired encript string with key after authenticate with fingerprint
                    SharedPreferences.Editor editor = sharedPref.edit();

                    byte[] enc = mCipher.doFinal(mToEncrypt.getBytes());
                    editor.putString("fing" + mKeyID, Base64.encodeToString(enc, Base64.DEFAULT));
                    editor.putString("fing_iv" + mKeyID,
                            Base64.encodeToString(mCipher.getIV(), Base64.DEFAULT));

                    editor.commit();
                    mToEncrypt = "";
                    result = "success";
                }
            }
        } catch (BadPaddingException e) {
            errorMessage = "Failed to encrypt the data with the generated key:"
                    + " BadPaddingException:  "
                    + e.getMessage();
            Log.e(TAG, errorMessage);
        } catch (IllegalBlockSizeException e) {
            errorMessage = "Failed to encrypt the data with the generated key: "
                    + "IllegalBlockSizeException: "
                    + e.getMessage();
            Log.e(TAG, errorMessage);
        }

        if (!result.equals("")) {
            mPluginResult = new PluginResult(PluginResult.Status.OK, result);
            mPluginResult.setKeepCallback(false);
        } else {
            mPluginResult = new PluginResult(PluginResult.Status.ERROR, errorMessage);
            mPluginResult.setKeepCallback(false);
        }
        mCallbackContext.sendPluginResult(mPluginResult);
    }

    private void removePermanentlyInvalidatedKey() {
        try {
            mKeyStore.deleteEntry(CLIENT_ID);
            Log.i(TAG, "Permanently invalidated key was removed.");
        } catch (KeyStoreException e) {
            Log.e(TAG, e.getMessage());
        }
    }

    private String createErrorMessage(final String errorCode, final String errorMessage) {
        JSONObject resultJson = new JSONObject();
        try {
            resultJson.put(OS, ANDROID);
            resultJson.put(ERROR_CODE, errorCode);
            resultJson.put(ERROR_MESSAGE, errorMessage);
            return resultJson.toString();
        } catch (JSONException e) {
            Log.e(TAG, e.getMessage());
        }
        return "";
    }

}
