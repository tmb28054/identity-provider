// Passkey (WebAuthn) client helpers.
//
// Served under the app's own origin so it loads under the existing
// `script-src 'self'` Content-Security-Policy with no relaxation. No inline
// event handlers are used; controls are wired up via addEventListener so the
// strict CSP (no 'unsafe-inline') is honoured.
//
// The server speaks JSON at the *_begin / *_finish endpoints. Options and
// assertions are exchanged as base64url so they survive JSON transport; this
// file converts to/from the ArrayBuffers the WebAuthn API requires.
"use strict";

(function () {
  function b64urlToBuf(value) {
    const pad = "=".repeat((4 - (value.length % 4)) % 4);
    const base64 = (value + pad).replace(/-/g, "+").replace(/_/g, "/");
    const raw = atob(base64);
    const buf = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i += 1) {
      buf[i] = raw.charCodeAt(i);
    }
    return buf.buffer;
  }

  function bufToB64url(buf) {
    const bytes = new Uint8Array(buf);
    let str = "";
    for (let i = 0; i < bytes.length; i += 1) {
      str += String.fromCharCode(bytes[i]);
    }
    return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  // Convert server registration options (base64url) into the shape
  // navigator.credentials.create() expects (ArrayBuffers).
  function toCreateOptions(options) {
    const publicKey = Object.assign({}, options);
    publicKey.challenge = b64urlToBuf(options.challenge);
    publicKey.user = Object.assign({}, options.user, {
      id: b64urlToBuf(options.user.id),
    });
    if (Array.isArray(options.excludeCredentials)) {
      publicKey.excludeCredentials = options.excludeCredentials.map(function (c) {
        return Object.assign({}, c, { id: b64urlToBuf(c.id) });
      });
    }
    return publicKey;
  }

  function toGetOptions(options) {
    const publicKey = Object.assign({}, options);
    publicKey.challenge = b64urlToBuf(options.challenge);
    if (Array.isArray(options.allowCredentials)) {
      publicKey.allowCredentials = options.allowCredentials.map(function (c) {
        return Object.assign({}, c, { id: b64urlToBuf(c.id) });
      });
    }
    return publicKey;
  }

  function registrationToJSON(cred) {
    const response = cred.response;
    return {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      response: {
        attestationObject: bufToB64url(response.attestationObject),
        clientDataJSON: bufToB64url(response.clientDataJSON),
        transports:
          typeof response.getTransports === "function"
            ? response.getTransports()
            : [],
      },
      clientExtensionResults: cred.getClientExtensionResults
        ? cred.getClientExtensionResults()
        : {},
    };
  }

  function assertionToJSON(cred) {
    const response = cred.response;
    return {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      response: {
        authenticatorData: bufToB64url(response.authenticatorData),
        clientDataJSON: bufToB64url(response.clientDataJSON),
        signature: bufToB64url(response.signature),
        userHandle: response.userHandle
          ? bufToB64url(response.userHandle)
          : null,
      },
      clientExtensionResults: cred.getClientExtensionResults
        ? cred.getClientExtensionResults()
        : {},
    };
  }

  async function postJSON(url, body) {
    const resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify(body),
    });
    const data = await resp.json().catch(function () {
      return {};
    });
    if (!resp.ok) {
      throw new Error(data.error || "Request failed (" + resp.status + ").");
    }
    return data;
  }

  // Register a new passkey from the /user page. Requires the step-up token and
  // CSRF token rendered into the form's data attributes.
  async function registerPasskey(opts) {
    const begin = await postJSON(opts.beginUrl, {
      csrf_token: opts.csrfToken,
      auth_token: opts.authToken,
    });
    const publicKey = toCreateOptions(begin.options);
    const credential = await navigator.credentials.create({ publicKey: publicKey });
    return postJSON(opts.finishUrl, {
      csrf_token: opts.csrfToken,
      auth_token: opts.authToken,
      handle: begin.handle,
      credential: registrationToJSON(credential),
    });
  }

  // Authenticate with a passkey from a login form (second factor / passwordless).
  async function authenticatePasskey(opts) {
    const begin = await postJSON(opts.beginUrl, {
      csrf_token: opts.csrfToken,
      username: opts.username,
    });
    const publicKey = toGetOptions(begin.options);
    const assertion = await navigator.credentials.get({ publicKey: publicKey });
    return postJSON(opts.finishUrl, {
      csrf_token: opts.csrfToken,
      handle: begin.handle,
      credential: assertionToJSON(assertion),
    });
  }

  function wireRegisterButton() {
    const btn = document.getElementById("passkey-register");
    if (!btn) {
      return;
    }
    const status = document.getElementById("passkey-status");
    btn.addEventListener("click", async function () {
      if (status) {
        status.style.color = "";
        status.textContent = "Follow your browser's prompts...";
      }
      try {
        const result = await registerPasskey({
          beginUrl: btn.dataset.beginUrl,
          finishUrl: btn.dataset.finishUrl,
          csrfToken: btn.dataset.csrf,
          authToken: btn.dataset.authToken,
        });
        // Update the list in place rather than reloading — the enroll page is
        // reached via POST, so a reload would re-submit the login form.
        if (result.credential) {
          appendCredential(btn, result.credential);
        }
        if (status) {
          status.style.color = "#1d8102";
          status.textContent = "Passkey registered.";
        }
      } catch (err) {
        if (status) {
          status.style.color = "";
          status.textContent = "Registration failed: " + err.message;
        }
      }
    });
  }

  // Append a freshly registered credential to the on-page list without a reload.
  function appendCredential(btn, credential) {
    const list = document.getElementById("passkey-list");
    if (!list) {
      return;
    }
    const empty = document.getElementById("passkey-empty");
    if (empty) {
      empty.style.display = "none";
    }
    const li = document.createElement("li");
    li.style.cssText =
      "display:flex;justify-content:space-between;align-items:center;" +
      "border:1px solid #eee;border-radius:4px;padding:0.5rem 0.75rem;margin-bottom:0.5rem;";
    const span = document.createElement("span");
    span.style.fontSize = "0.9rem";
    span.textContent = credential.label || "passkey";
    const form = document.createElement("form");
    form.method = "post";
    form.style.cssText = "margin:0;width:auto;";
    const fields = {
      csrf_token: btn.dataset.csrf,
      action: "remove_passkey",
      auth_token: btn.dataset.authToken,
      credential_id: credential.credential_id,
    };
    Object.keys(fields).forEach(function (name) {
      const input = document.createElement("input");
      input.type = "hidden";
      input.name = name;
      input.value = fields[name];
      form.appendChild(input);
    });
    const remove = document.createElement("button");
    remove.className = "btn-danger";
    remove.style.cssText =
      "width:auto;padding:0.35rem 0.75rem;margin:0;font-size:0.8rem;";
    remove.textContent = "Remove";
    form.appendChild(remove);
    li.appendChild(span);
    li.appendChild(form);
    list.appendChild(li);
  }

  function wireLoginButton() {
    const btn = document.getElementById("passkey-login");
    if (!btn) {
      return;
    }
    const status = document.getElementById("passkey-status");
    btn.addEventListener("click", async function () {
      const usernameField = document.getElementById("username");
      const username = usernameField ? usernameField.value : "";
      if (!username) {
        if (status) {
          status.textContent = "Enter your username first.";
        }
        return;
      }
      if (status) {
        status.textContent = "Follow your browser's prompts...";
      }
      try {
        const result = await authenticatePasskey({
          beginUrl: btn.dataset.beginUrl,
          finishUrl: btn.dataset.finishUrl,
          csrfToken: btn.dataset.csrf,
          username: username,
        });
        if (result.redirect) {
          window.location.href = result.redirect;
        } else if (result.html) {
          document.open();
          document.write(result.html);
          document.close();
        } else {
          window.location.reload();
        }
      } catch (err) {
        if (status) {
          status.textContent = "Sign-in failed: " + err.message;
        }
      }
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    wireRegisterButton();
    wireLoginButton();
  });
})();
