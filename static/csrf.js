/* Adds the session CSRF token to all unsafe fetch requests. */
(() => {
  const meta = document.querySelector('meta[name="csrf-token"]');
  if (!meta || !meta.content) return;

  const token = meta.content;
  const originalFetch = window.fetch.bind(window);

  window.fetch = (input, init = {}) => {
    const requestMethod = (
      init.method || (input instanceof Request ? input.method : "GET")
    ).toUpperCase();

    if (!["GET", "HEAD", "OPTIONS", "TRACE"].includes(requestMethod)) {
      const inheritedHeaders = input instanceof Request ? input.headers : undefined;
      const headers = new Headers(init.headers || inheritedHeaders || {});
      if (!headers.has("X-CSRF-Token")) {
        headers.set("X-CSRF-Token", token);
      }
      init = { ...init, headers };
    }

    return originalFetch(input, init);
  };

  // Backstop for dynamically-created forms that do not include a hidden token.
  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    if ((form.method || "GET").toUpperCase() === "GET") return;
    if (form.querySelector('input[name="csrf_token"]')) return;

    const input = document.createElement("input");
    input.type = "hidden";
    input.name = "csrf_token";
    input.value = token;
    form.appendChild(input);
  }, true);
})();
