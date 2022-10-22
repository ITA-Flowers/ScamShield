package pl.edu.wat.scamshield;

import android.content.Context;
import android.webkit.JavascriptInterface;

public class JavaScriptInterface {
    Context mContext;
    String actualUrl;
    JavaScriptInterface(Context c){
        this.mContext = c;
    }

    @JavascriptInterface
    public String getSafeUrlFromAndroid(){
        return "https://www.google.com";
    }

    @JavascriptInterface
    public String getActualUrlFromAndroid() {
        return actualUrl;
    }

    public void setActualUrl(String actualUrl){
        this.actualUrl = actualUrl;
    }
}
