// -- Error log
function onError(error) {
    console.error(`Error: ${error}`)
}

// LISTENERS
// ---------
// -- Runtime Messages Listener
chrome.runtime.onMessage.addListener((request) => {
    if (request.type === 'ALERT') {
        console.warn(`Trustscore: ${request.score}`)
        alert(`Ta strona może być niebezpieczna!\nTrustscore : [${request.score}]`)
    }
});