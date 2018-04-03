package com.cordova.plugin.android.fingerprintauth;

import android.annotation.TargetApi;
import android.util.Log;
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
  // Plugin response codes and messages
  private static final String OS = "OS";
  private static final String ANDROID = "Android";
  private static final String ERROR_CODE = "ErrorCode";
  private static final String ERROR_MESSAGE = "ErrorMessage";
  private static final String NO_HARDWARE_CODE = "-6";
  private static final String NO_HARDWARE_MESSAGE = "Biometry is not available on this device.";

  /**
   * Alias for our key in the Android Key Store
   */
  public static String packageName;
  public static CallbackContext mCallbackContext;
  public static PluginResult mPluginResult;

  public FingerprintAuthAux mFingerprintAuthAux;
  /**
   * Constructor.
   */
  public FingerprintAuth() {
  }

  public static void onCancelled() {
    mCallbackContext.error("Cancelled");
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

    packageName = cordova.getActivity().getApplicationContext().getPackageName();
    mPluginResult = new PluginResult(PluginResult.Status.NO_RESULT);



    if (android.os.Build.VERSION.SDK_INT < 23) {
      return;
    }
    if (mFingerprintAuthAux == null) {
      mFingerprintAuthAux = new FingerprintAuthAux(this);
    }

    mFingerprintAuthAux.initialize(cordova, webView);

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
          
    if (android.os.Build.VERSION.SDK_INT < 23) {
      String errorMessage = createErrorMessage(NO_HARDWARE_CODE, NO_HARDWARE_MESSAGE);
      mPluginResult = new PluginResult(PluginResult.Status.ERROR, errorMessage);
      mCallbackContext.sendPluginResult(mPluginResult);
      return true;
    }

    if (mFingerprintAuthAux == null) {
      mFingerprintAuthAux = new FingerprintAuthAux(this);
    }


    return mFingerprintAuthAux.execute(action, args, callbackContext, cordova);

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
