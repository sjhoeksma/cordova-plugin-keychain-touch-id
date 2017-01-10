package com.cordova.plugin.android.fingerprintauth;

import android.annotation.TargetApi;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.SharedPreferences;
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
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

@TargetApi(23) public class FingerprintAuth extends CordovaPlugin {

  public static final String TAG = "FingerprintAuth";
  private static final String DIALOG_FRAGMENT_TAG = "FpAuthDialog";
  private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
  /**
   * Alias for our key in the Android Key Store
   */
  private final static String mClientId = "CordovaTouchPlugin";
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
  /**
   * String to encrypt
   */
  private String mToEncrypt;

  /**
   * Constructor.
   */
  public FingerprintAuth() {
  }

  /**
   * Creates a symmetric key in the Android Key Store which can only be used after the user has
   * authenticated with fingerprint.
   */
  public static boolean createKey() {
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
      mKeyGenerator.init(new KeyGenParameterSpec.Builder(mClientId,
          KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT).setBlockModes(
          KeyProperties.BLOCK_MODE_CBC)
          // Require the user to authenticate with a fingerprint to authorize every use
          // of the key
          .setUserAuthenticationRequired(false)
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
    super.initialize(cordova, webView);
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
  public boolean execute(final String action, JSONArray args, CallbackContext callbackContext)
      throws JSONException {
    mCallbackContext = callbackContext;
    Log.v(TAG, "FingerprintAuth action: " + action);
    if (android.os.Build.VERSION.SDK_INT < 23) {
      Log.e(TAG, "minimum SDK version 23 required");
      JSONObject resultJson = new JSONObject();
      resultJson.put("OS", "Android");
      resultJson.put("ErrorCode", "-6");
      resultJson.put("ErrorMessage", "Biometry is not available on this device.");
      mPluginResult = new PluginResult(PluginResult.Status.ERROR);
      mCallbackContext.error(resultJson.toString());
      mCallbackContext.sendPluginResult(mPluginResult);
      return true;
    }
    if (action.equals("save")) {
      final String key = args.getString(0);
      final String password = args.getString(1);

      if (isFingerprintAuthAvailable()) {
        SecretKey secretKey = getSecretKey();
        boolean isCipherInit = true;
        if (secretKey == null) {
          if (createKey()) {
            secretKey = getSecretKey();
          }
        }
        mKeyID = key;
        mToEncrypt = password;
        SharedPreferences sharedPref = cordova.getActivity().getPreferences(Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = sharedPref.edit();
        if (initCipher(Cipher.ENCRYPT_MODE)) {
          byte[] enc = new byte[0];
          try {
            enc = mCipher.doFinal(mToEncrypt.getBytes());

            editor.putString("fing" + mKeyID, Base64.encodeToString(enc, Base64.DEFAULT));
            editor.putString("fing_iv" + mKeyID, Base64.encodeToString(mCipher.getIV(), Base64.DEFAULT));

            editor.apply();
            mCallbackContext.success("Success");
            mPluginResult = new PluginResult(PluginResult.Status.OK);
            mCallbackContext.sendPluginResult(mPluginResult);
            return true;
          } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
            mCallbackContext.success("Error string is to big.");
            mPluginResult = new PluginResult(PluginResult.Status.ERROR);
            mCallbackContext.sendPluginResult(mPluginResult);
          } catch (BadPaddingException e) {
            e.printStackTrace();
            mCallbackContext.success("Error Bad Padding");
            mPluginResult = new PluginResult(PluginResult.Status.ERROR);
            mCallbackContext.sendPluginResult(mPluginResult);
          }
        }
      } else {
        mCallbackContext.error("Fingerprint authentication not available");
        mPluginResult = new PluginResult(PluginResult.Status.ERROR);
        mCallbackContext.sendPluginResult(mPluginResult);
      }
      return true;
    } else if (action.equals("verify")) {
      final String key = args.getString(0);
      final String message = args.getString(1);

      JSONObject resultJson = new JSONObject();
      resultJson.put("OS", "Android");

      if (isHardwareDetected()) {
        if (hasEnrolledFingerprints()){
          SecretKey secretKey = getSecretKey();
          if (secretKey != null) {
            mKeyID = key;
            showFingerprintDialog(Cipher.DECRYPT_MODE, message);
            mPluginResult.setKeepCallback(true);
          } else {
            mPluginResult = new PluginResult(PluginResult.Status.ERROR);
            resultJson.put("ErrorCode", "-5");
            resultJson.put("ErrorMessage", "Secret Key not set.");
            mCallbackContext.error(resultJson.toString());
            mCallbackContext.sendPluginResult(mPluginResult);
          }
        }
        else{
          resultJson.put("ErrorCode", "-7");
          resultJson.put("ErrorMessage", "No fingers are enrolled with Touch ID.");
          mPluginResult = new PluginResult(PluginResult.Status.ERROR);
          mCallbackContext.error(resultJson.toString());
          mCallbackContext.sendPluginResult(mPluginResult);
        }
      } else {
        resultJson.put("ErrorCode", "-6");
        resultJson.put("ErrorMessage", "Biometry is not available on this device.");
        mPluginResult = new PluginResult(PluginResult.Status.ERROR);
        mCallbackContext.error(resultJson.toString());
        mCallbackContext.sendPluginResult(mPluginResult);
      }
      return true;
    } else if (action.equals("isAvailable")) {
      JSONObject resultJson = new JSONObject();
      resultJson.put("OS", "Android");
      if (isHardwareDetected()) {
        if (hasEnrolledFingerprints()){

          mPluginResult = new PluginResult(PluginResult.Status.OK);
          mCallbackContext.success("YES");
          mCallbackContext.sendPluginResult(mPluginResult);
        }
        else{
          resultJson.put("ErrorCode", "-7");
          resultJson.put("ErrorMessage", "No fingers are enrolled with Touch ID.");
          mPluginResult = new PluginResult(PluginResult.Status.ERROR);
          mCallbackContext.error(resultJson.toString());
          mCallbackContext.sendPluginResult(mPluginResult);
        }
      } else {
        resultJson.put("ErrorCode", "-6");
        resultJson.put("ErrorMessage", "Biometry is not available on this device.");
        mPluginResult = new PluginResult(PluginResult.Status.ERROR);
        mCallbackContext.error(resultJson.toString());
        mCallbackContext.sendPluginResult(mPluginResult);
      }
      return true;
    } else if (action.equals("setLocale")) {            // Set language
      mLangCode = args.getString(0);
      Resources res = cordova.getActivity().getResources();
      // Change locale settings in the app.
      DisplayMetrics dm = res.getDisplayMetrics();
      Configuration conf = res.getConfiguration();
      conf.locale = new Locale(mLangCode.toLowerCase());
      res.updateConfiguration(conf, dm);
      return true;
    } else if (action.equals("has")) { //if has key
      String key = args.getString(0);
      SharedPreferences sharedPref = cordova.getActivity().getPreferences(Context.MODE_PRIVATE);
      String enc = sharedPref.getString("fing" + key, "");
      if (!enc.equals("")) {
        mPluginResult = new PluginResult(PluginResult.Status.OK);
        mCallbackContext.success();
        mCallbackContext.sendPluginResult(mPluginResult);
      } else {
        mPluginResult = new PluginResult(PluginResult.Status.ERROR);
        mCallbackContext.error("No pw available");
        mCallbackContext.sendPluginResult(mPluginResult);
      }
      return true;
    } else if (action.equals("delete")) { //delete key
      final String key = args.getString(0);
      SharedPreferences sharedPref = cordova.getActivity().getPreferences(Context.MODE_PRIVATE);
      SharedPreferences.Editor editor = sharedPref.edit();
      editor.remove("fing" + key);
      editor.remove("fing_iv" + key);
      boolean removed = editor.commit();
      if (removed) {
        mPluginResult = new PluginResult(PluginResult.Status.OK);
        mCallbackContext.success();
      } else {
        mPluginResult = new PluginResult(PluginResult.Status.ERROR);
        mCallbackContext.error("Could not delete password");
      }
      mCallbackContext.sendPluginResult(mPluginResult);
      return true;
    }
    return false;
  }

  private boolean isFingerprintAuthAvailable() {
    return isHardwareDetected()
        && hasEnrolledFingerprints();
  }

  private boolean isHardwareDetected() {
    return mFingerPrintManager.isHardwareDetected();
  }

  private boolean hasEnrolledFingerprints() {
    return mFingerPrintManager.hasEnrolledFingerprints();
  }

  /**
   * Initialize the {@link Cipher} instance with the created key in the {@link #createKey()}
   * method.
   *
   * @return {@code true} if initialization is successful, {@code false} if the lock screen has
   * been disabled or reset after the key was generated, or if a fingerprint got enrolled after
   * the key was generated.
   */
  private boolean initCipher(int mode) {
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
        SharedPreferences sharedPref = cordova.getActivity().getPreferences(Context.MODE_PRIVATE);
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
      key = (SecretKey) mKeyStore.getKey(mClientId, null);
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

  public void showFingerprintDialog(final int mode, final String message) {
    final FingerprintAuth auth = this;
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

        if (initCipher(mode)) {
          mFragment.setCancelable(false);
          // Show the fingerprint dialog. The user has the option to use the fingerprint with
          // crypto, or you can fall back to using a server-side verified password.
          mFragment.setCryptoObject(new FingerprintManager.CryptoObject(mCipher));
          mFragment.show(cordova.getActivity().getFragmentManager(), DIALOG_FRAGMENT_TAG);
        } else {
          mCallbackContext.error("Failed to init Cipher");
          mPluginResult = new PluginResult(PluginResult.Status.ERROR);
          mCallbackContext.sendPluginResult(mPluginResult);
        }
      }
    });
  }

  public void onAuthenticated(boolean withFingerprint) {
    String result = "";
    String errorMessage = "";
    try {

      if (withFingerprint) {
        // If the user has authenticated with fingerprint, verify that using cryptography and
        // then return the encrypted token
        SharedPreferences sharedPref = cordova.getActivity().getPreferences(Context.MODE_PRIVATE);
        if (mCurrentMode == Cipher.DECRYPT_MODE) {
          byte[] enc = Base64.decode(sharedPref.getString("fing" + mKeyID, ""), Base64.DEFAULT);

          byte[] decrypted = mCipher.doFinal(enc);
          String decrString = new String(decrypted);
          result = decrString;
        }
      }
    } catch (BadPaddingException e) {
      errorMessage = "Failed to encrypt the data with the generated key:" +
          " BadPaddingException:  " + e.getMessage();
      Log.e(TAG, errorMessage);
    } catch (IllegalBlockSizeException e) {
      errorMessage = "Failed to encrypt the data with the generated key: " +
          "IllegalBlockSizeException: " + e.getMessage();
      Log.e(TAG, errorMessage);
    }

    if (result != "") {
      mCallbackContext.success(result);
      mPluginResult = new PluginResult(PluginResult.Status.OK);
    } else {
      mCallbackContext.error(errorMessage);
      mPluginResult = new PluginResult(PluginResult.Status.ERROR);
    }
    mCallbackContext.sendPluginResult(mPluginResult);
  }

  private void removePermanentlyInvalidatedKey() {
    try {
      mKeyStore.deleteEntry(mClientId);
      Log.i(TAG, "Permanently invalidated key was removed.");
    } catch (KeyStoreException e) {
      Log.e(TAG, e.getMessage());
    }
  }
}
