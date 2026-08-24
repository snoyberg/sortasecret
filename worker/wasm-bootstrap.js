import * as imports from "./sortasecret_bg.js";
import wasmModule from "./sortasecret_bg.wasm";

const instance = new WebAssembly.Instance(wasmModule, {
  "./sortasecret_bg.js": imports,
});
imports.__wbg_set_wasm(instance.exports);

export * from "./sortasecret_bg.js";
