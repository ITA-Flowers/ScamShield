var actualUrl = "null";
var safeUrl = "null";

function initPage() {
    actualUrl = Android.getActualUrlFromAndroid();
    safeUrl = Android.getSafeUrlFromAndroid();
    document.getElementById("url").innerHTML = actualUrl;
}

function btn1_click(){
    window.location.assign("http://www."+actualUrl)
}

function btn2_click(){
    window.location.assign(safeUrl)
}