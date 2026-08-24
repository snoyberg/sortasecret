import { respond_wrapper } from "./pkg/sortasecret.js";

export default {
  async fetch(request, env) {
    return respond_wrapper(
      request,
      env.SORTASECRET_RECAPTCHA_SECRET,
      env.SORTASECRET_RECAPTCHA_SITE,
      env.SORTASECRET_KEYPAIR,
    );
  },
};
