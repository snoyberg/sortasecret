(() => {
  var script = document.createElement("script");
  script.setAttribute("src", "https://www.google.com/recaptcha/api.js?render={{ site }}");
  document.head.appendChild(script);
})();

function sortasecret() {
  var button = document.getElementById("sortasecret-demo-button");
  var demoSecret = document.getElementById("sortasecret-demo-secret");

  function showRevealError(error) {
    console.error("Sorta Secret reveal failed:", error);
    if (demoSecret) {
      demoSecret.textContent = "The message could not be revealed. Please try again.";
    }
    if (button) {
      button.disabled = false;
      button.textContent = "Try again";
    }
  }

  if (button) {
    button.disabled = true;
    button.textContent = "Checking…";
  }
  if (demoSecret) {
    demoSecret.textContent = "Checking reCAPTCHA…";
  }

  if (!window.grecaptcha || typeof window.grecaptcha.ready !== "function") {
    showRevealError(new Error("Google reCAPTCHA is not available"));
    return;
  }

  window.grecaptcha.ready(() => {
    window.grecaptcha.execute("{{ site }}", { action: "homepage" }).then((token) => {
      var secrets = [];
      var nodes = document.querySelectorAll("[data-sortasecret]");
      for (var i = 0; i < nodes.length; ++i) {
        secrets.push(nodes[i].getAttribute("data-sortasecret"));
      }

      return fetch("/v1/decrypt", {
        method: "PUT",
        body: JSON.stringify({ token: token, secrets: secrets }),
        headers: { "content-type": "application/json" },
      });
    }).then((res) => {
      if (!res.ok) {
        throw new Error("Reveal request failed with status " + res.status);
      }
      return res.json();
    }).then((response) => {
      var nodes = document.querySelectorAll("[data-sortasecret]");
      for (var i = 0; i < nodes.length; ++i) {
        var node = nodes[i];
        var key = node.getAttribute("data-sortasecret");
        node.textContent = response.decrypted[key];
      }
      if (button) {
        button.textContent = "Message revealed";
      }
    }).catch(showRevealError);
  });
}
