(() => {
var script = document.createElement("script");
script.setAttribute("src", "https://www.google.com/recaptcha/api.js?render={{ site }}");
document.head.appendChild(script);
})()
function sortasecret() {
  grecaptcha.ready(() => {
    grecaptcha.execute("{{ site }}", {action: "homepage"}).then((token) => {
      var secrets = [], nodes = document.querySelectorAll("[data-sortasecret]");
      for (var i = 0; i < nodes.length; ++i) {
        secrets.push(nodes[i].getAttribute("data-sortasecret"));
      }
      fetch("/v1/decrypt", {
        method: "PUT",
        body: JSON.stringify({token: token, secrets: secrets}),
        headers: {"content-type": "application/json"},
      }).then(res => res.json())
      .then(response => {
        var nodes = document.querySelectorAll("[data-sortasecret]");
        for (var i = 0; i < nodes.length; ++i) {
          var node = nodes[i];
          var key = node.getAttribute("data-sortasecret");
          var decrypted = response.decrypted[key];
          node.innerText = decrypted;
        }
      })
      .catch(error => console.log("Error: ", JSON.stringify(error)))
    });
  });
}
