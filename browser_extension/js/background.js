// FILTERS
// -------
// -- HTTPS Sites Filter
const securePageFilter = { 
    url: 
    [
        { 
            urlPrefix: "https://"
        }
    ]
}

// -- HTTP Sites Filter
const insecurePageFilter = { 
    url: 
    [
        { 
            urlPrefix: "http://"
        }
    ]
}

// LISTENERS
// ---------
// -- Page Load Listener - HTTPS - SECURE
chrome.webNavigation.onCompleted.addListener(() => {
        handlePageLoad('SECURE')
    },
    securePageFilter
);

// -- Page Load Listener - HTTP - INSECURE
chrome.webNavigation.onCompleted.addListener(() => {
        handlePageLoad('INSECURE')
    },
    insecurePageFilter
);

// API
// ---
// -- API Endpoint
const apiUrl = 'http://127.0.0.1:8080/api/url'

// FUNCTIONS
// ---------

// -- Handle Response
function handleResponse(response) {
  console.debug(`RESPONSE: ${response.msg}`);
}

// -- Handle Error
function handleError(error) {
  console.error(`Error: ${error}`);
}

// -- Page Load Handler
async function handlePageLoad(pageType)
{
    const queryOptions = { active: true, lastFocusedWindow: true };

    let tabs = await chrome.tabs.query(queryOptions);
    if (!tabs.length) return;

    var activeTab = tabs[0];
    var activeTabId = activeTab.id;
    var activeTabUrlFull = activeTab.url; // full url address

    let index = activeTabUrlFull.indexOf('/', 8)
    var activeTabUrl = activeTabUrlFull.substring(0, index + 1) // only domain address

    var requestBody = JSON.stringify({url : activeTabUrl});

    console.debug('REQUEST:');
    console.log(requestBody);

    await fetch(apiUrl,
        {
            method: "POST",
            headers: {'Content-Type': 'application/json'},
            body: requestBody
        })
        .then(function(response){ 
            console.debug(response.status)
            return response.json(); 
        })
        .then(function(data){
            if (!data.hasOwnProperty("error")) {
                // RESPONSE STATUS OK
                console.log(`DOMAIN: ${data.domain}`);
                console.log(`SCORE:  ${data.phishing_estimate}`);
                if (data.phishing_estimate != "0") {
                    chrome.runtime.sendMessage({ type: 'ALERT', score: data.phishing_estimate });
                }
            } else {
                // RESPONSE STATUS ERROR
                console.log(`URL: ${activeTabUrl}`)
                console.log(`ERROR: ${data.error}`);
            }
        })
        .catch((reason) => {
            // NO RESPONSE
            console.debug(`Error: ${reason}`);
            console.log(`Error: URL: ${activeTabUrl}`);
        });
}