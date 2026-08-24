import { respond_wrapper } from "./pkg/sortasecret.js";

export default {
  async fetch(request) {
    return respond_wrapper(request);
  },
};
