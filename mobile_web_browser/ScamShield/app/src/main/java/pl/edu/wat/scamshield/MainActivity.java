package pl.edu.wat.scamshield;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Intent;
import android.graphics.Bitmap;
import android.os.Bundle;
import android.util.Log;
import android.util.Patterns;
import android.view.MenuItem;
import android.view.View;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputMethodManager;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.PopupMenu;
import android.widget.ProgressBar;

import androidx.appcompat.app.AppCompatActivity;

import com.android.volley.Request;
import com.android.volley.RequestQueue;
import com.android.volley.toolbox.JsonObjectRequest;
import com.android.volley.toolbox.Volley;

import org.json.JSONException;
import org.json.JSONObject;

public class MainActivity extends AppCompatActivity implements PopupMenu.OnMenuItemClickListener{

    EditText inputFieldURL;
    WebView webView;
    ProgressBar progressBar;
    ImageView goBack, goForward, refresh, share, clearFieldURL, menu;
    LinearLayout bottomLayout;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        initFrontComponents();
        initFrontComponentsListeners();
        initWebSettings();
        try {
            searchWithGoogle("google.com");
        } catch (JSONException e) {
            e.printStackTrace();
        }
    }

    private void initFrontComponents(){
        inputFieldURL = findViewById(R.id.editText_inputURL);
        clearFieldURL = findViewById(R.id.imageView_iconCancel);
        menu = findViewById(R.id.imageView_iconMenu);
        progressBar = findViewById(R.id.ProgressBar);
        webView = findViewById(R.id.WebView);
        bottomLayout = findViewById(R.id.LinearLayout_bottomLayout);
        goBack = findViewById(R.id.imageView_goBack);
        goForward = findViewById(R.id.imageView_goForward);
        refresh = findViewById(R.id.imageView_refresh);
        share = findViewById(R.id.imageView_share);
    }

    private void initFrontComponentsListeners(){
        inputFieldURL.setOnEditorActionListener((textView, i, keyEvent) -> {
            if(i == EditorInfo.IME_ACTION_GO || i == EditorInfo.IME_ACTION_DONE){
                InputMethodManager imm = (InputMethodManager) getSystemService(Activity.INPUT_METHOD_SERVICE);
                imm.hideSoftInputFromWindow(inputFieldURL.getWindowToken(),0);
                try {
                    searchWithGoogle(inputFieldURL.getText().toString());
                } catch (JSONException e) {
                    e.printStackTrace();
                }
                return true;
            }
            return false;
        });

        clearFieldURL.setOnClickListener(view -> inputFieldURL.setText(""));

        goBack.setOnClickListener(view -> {
            if(webView.canGoBack()){
                webView.goBack();
            }
        });

        goForward.setOnClickListener(view -> {
            if(webView.canGoForward()){
                webView.goForward();
            }
        });

        refresh.setOnClickListener(view -> webView.reload());

        share.setOnClickListener(view -> {
            Intent intent = new Intent(Intent.ACTION_VIEW);
            intent.setAction(Intent.ACTION_SEND);
            intent.putExtra(Intent.EXTRA_TEXT, webView.getUrl());
            intent.setType("text/plain");
            startActivity(intent);
        });

        menu.setOnClickListener(this::showPopupMenu);
    }

    @SuppressLint("SetJavaScriptEnabled")
    private void initWebSettings(){
        WebSettings webSettings = webView.getSettings();
        webSettings.setJavaScriptEnabled(true);
        webSettings.setBuiltInZoomControls(true);
        webSettings.setDisplayZoomControls(false);

        webView.setWebViewClient(new ScamShieldWebViewClient());
        webView.setWebChromeClient(new WebChromeClient(){

            @Override
            public void onProgressChanged(WebView view, int newProgress) {
                super.onProgressChanged(view, newProgress);
                progressBar.setProgress(newProgress);
            }
        });
    }

    private void searchWithGoogle(String insertedUrl) throws JSONException {
        boolean matchUrl = Patterns.WEB_URL.matcher(insertedUrl).matches();
        if(matchUrl){
            webView.loadUrl(insertedUrl);
            sendRequestAboutUrl(insertedUrl);

        }else{
            String newUrl = "google.com/search?q="+insertedUrl;
            webView.loadUrl(newUrl);
            sendRequestAboutUrl(newUrl);
        }
    }

    private void sendRequestAboutUrl(String insertedUrl) throws JSONException {
        String insertedUrlAsJson = "{\'url\': \'"+insertedUrl+"\'}";
        JSONObject jsonObject = new JSONObject(insertedUrlAsJson);
        String requestURL = "http://10.104.10.25:8080/api/url";
        RequestQueue requestQueue = Volley.newRequestQueue(this);
        JsonObjectRequest objectRequest = new JsonObjectRequest(
                Request.Method.POST, requestURL, jsonObject,
                response -> {
                    Log.e("Rest Response: ", response.toString());
                    String score;
                    try {
                        score =  response.getString("phishing_estimate");
                        if(!score.equals("0")){
                            JavaScriptInterface javaScriptInterface = new JavaScriptInterface(this);
                            javaScriptInterface.setActualUrl(insertedUrl);
                            webView.addJavascriptInterface(javaScriptInterface, "Android");
                            webView.loadUrl("file:///android_asset/mobile_errorPage.html");
                        }
                    } catch (JSONException e) {
                        e.printStackTrace();
                    }
                },
                error -> Log.e("Rest Response: ", error.toString())
        );
        requestQueue.add(objectRequest);
    }

    @Override
    public void onBackPressed() {
        if(webView.canGoBack()){
            webView.goBack();
        }else{
            super.onBackPressed();
        }
    }

    public void showPopupMenu(View v){
        PopupMenu popup = new PopupMenu(this, v);
        popup.setOnMenuItemClickListener(this);
        popup.inflate(R.menu.main_menu);
        popup.show();
    }

    @SuppressLint("NonConstantResourceId")
    @Override
    public boolean onMenuItemClick(MenuItem menuItem) {
        switch(menuItem.getItemId()){
            case R.id.browserHistory:
            case R.id.credits:
            case R.id.domainWhiteList:
            case R.id.domainBlackList:
                System.out.println("NOT IMPLEMENTED YET!");
                return true;
            default:
                return false;
        }
    }

    class ScamShieldWebViewClient extends WebViewClient{
        @Override
        public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
            return false;
        }

        @Override
        public void onPageStarted(WebView view, String url, Bitmap favicon) {
            super.onPageStarted(view, url, favicon);
            inputFieldURL.setText(webView.getUrl());
            progressBar.setVisibility(View.VISIBLE);
        }

        @Override
        public void onPageFinished(WebView view, String url) {
            super.onPageFinished(view, url);
            progressBar.setVisibility(View.INVISIBLE);
        }
    }
}