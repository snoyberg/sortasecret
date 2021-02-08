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
    return await respond_wrapper(request)
}
