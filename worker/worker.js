addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

/**
 * Fetch and log a request
 * @param {Request} request
 */
async function handleRequest(request) {
    const { respond_wrapper } = wasm_bindgen;
    await wasm_bindgen(wasm)

    var body;
    if (request.body) {
        body = await request.text();
    } else {
        body = "";
    }

    var headers = {};
    for(var key of request.headers.keys()) {
        headers[key] = request.headers.get(key);
    }

    const response = await respond_wrapper({
        method: request.method,
        headers: headers,
        url: request.url,
        body: body,
    })
    return new Response(response.body, {
        status: response.status,
        headers: response.headers,
    })
}
