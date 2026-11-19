"""Static assets and strict HTML-escaped SSR renderer for ``review_web`` (zero inline JS/URLs)."""

from __future__ import annotations

import html
from collections.abc import Mapping

from superbrain.core.jsonvalue import JsonValue

__all__ = ["REVIEW_CSS", "REVIEW_JS", "render_review_html"]

REVIEW_CSS = """body {
  font-family: system-ui, -apple-system, sans-serif;
  margin: 2rem auto;
  max-width: 48rem;
  padding: 0 1rem;
  color: #1a1a1a;
  background: #fafafa;
}
.card {
  background: #ffffff;
  border: 1px solid #d4d4d8;
  border-radius: 8px;
  padding: 1.25rem;
  margin-bottom: 1rem;
}
.badge {
  display: inline-block;
  padding: 0.2rem 0.5rem;
  border-radius: 4px;
  background: #f4f4f5;
  font-family: monospace;
  font-size: 0.85rem;
}
button {
  padding: 0.6rem 1.1rem;
  border-radius: 6px;
  border: 1px solid #18181b;
  background: #18181b;
  color: #ffffff;
  cursor: pointer;
}
button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
pre {
  background: #f4f4f5;
  padding: 0.75rem;
  border-radius: 6px;
  overflow-x: auto;
  font-size: 0.85rem;
}
"""

REVIEW_JS = """(function () {
  "use strict";
  var statusEl = document.getElementById("status");
  var detailsEl = document.getElementById("details");
  var signerSelect = document.getElementById("signer-select");
  var actionSelect = document.getElementById("action-select");
  var submitBtn = document.getElementById("submit-btn");
  var csrfToken = null;
  var currentState = null;

  function setStatus(msg) {
    if (statusEl) {
      statusEl.textContent = String(msg);
    }
  }

  function b64uToBytes(value) {
    var padded = value.replace(/-/g, "+").replace(/_/g, "/");
    while (padded.length % 4 !== 0) {
      padded += "=";
    }
    var bin = window.atob(padded);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i += 1) {
      out[i] = bin.charCodeAt(i);
    }
    return out;
  }

  function bytesToB64u(buf) {
    var bytes = new Uint8Array(buf);
    var str = "";
    for (var i = 0; i < bytes.length; i += 1) {
      str += String.fromCharCode(bytes[i]);
    }
    return window.btoa(str).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/g, "");
  }

  function renderState(data) {
    currentState = data;
    if (detailsEl) {
      detailsEl.textContent = JSON.stringify(data.subject_summary || {}, null, 2);
    }
    if (signerSelect) {
      while (signerSelect.firstChild) {
        signerSelect.removeChild(signerSelect.firstChild);
      }
      var signers = data.signers || [];
      for (var i = 0; i < signers.length; i += 1) {
        var opt = document.createElement("option");
        opt.value = String(signers[i].signer_id || "");
        opt.textContent = String(signers[i].signer_id || "");
        signerSelect.appendChild(opt);
      }
    }
    if (submitBtn) {
      submitBtn.disabled = !csrfToken || !(data.signers && data.signers.length > 0);
    }
  }

  async function loadState() {
    var action = actionSelect ? actionSelect.value : "approve";
    var resp = await fetch("/api/state?action=" + encodeURIComponent(action), {
      method: "GET",
      credentials: "same-origin"
    });
    var env = await resp.json();
    if (!resp.ok || !env.ok) {
      setStatus("Failed to load review state: " + (env.error && env.error.code ? env.error.code : resp.status));
      return;
    }
    renderState(env.data);
    setStatus("Ready for passkey verification.");
  }

  async function bootstrapSession() {
    var hash = window.location.hash || "";
    var prefix = "#token=";
    if (!hash.startsWith(prefix)) {
      setStatus("Missing one-time bootstrap token in URL fragment.");
      return;
    }
    var token = hash.slice(prefix.length);
    if (window.history && window.history.replaceState) {
      window.history.replaceState(null, "", window.location.pathname);
    }
    var resp = await fetch("/api/session", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: token })
    });
    var env = await resp.json();
    if (!resp.ok || !env.ok) {
      setStatus("Session exchange failed.");
      return;
    }
    csrfToken = env.data.csrf_token;
    await loadState();
  }

  async function submitPasskey() {
    if (!csrfToken || !currentState) {
      setStatus("Session not initialized.");
      return;
    }
    var opts = currentState.webauthn_options;
    var pubKey = {
      challenge: b64uToBytes(opts.challenge),
      rpId: opts.rpId,
      timeout: opts.timeout || 60000,
      userVerification: opts.userVerification || "required",
      allowCredentials: (opts.allowCredentials || []).map(function (c) {
        return { type: "public-key", id: b64uToBytes(c.id) };
      })
    };
    var cred = await navigator.credentials.get({ publicKey: pubKey });
    var assertionPayload = {
      id: cred.id,
      rawId: bytesToB64u(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bytesToB64u(cred.response.clientDataJSON),
        authenticatorData: bytesToB64u(cred.response.authenticatorData),
        signature: bytesToB64u(cred.response.signature),
        userHandle: cred.response.userHandle ? bytesToB64u(cred.response.userHandle) : null
      }
    };
    var resp = await fetch("/api/submit", {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrfToken
      },
      body: JSON.stringify({
        action: currentState.action,
        signer_id: signerSelect ? signerSelect.value : "",
        challenge_message: currentState.challenge,
        response_json: JSON.stringify(assertionPayload)
      })
    });
    var env = await resp.json();
    if (!resp.ok || !env.ok) {
      var code = env.error && env.error.code ? env.error.code : String(resp.status);
      setStatus("Rejected (" + code + "). Refreshing state...");
      if (resp.status === 409) {
        await loadState();
      }
      return;
    }
    setStatus("Passkey approval committed.");
    if (submitBtn) {
      submitBtn.disabled = true;
    }
  }

  if (actionSelect) {
    actionSelect.addEventListener("change", function () {
      if (csrfToken) {
        loadState();
      }
    });
  }
  if (submitBtn) {
    submitBtn.addEventListener("click", function () {
      submitPasskey().catch(function (err) {
        setStatus("Passkey error: " + (err && err.message ? err.message : "failed"));
      });
    });
  }
  bootstrapSession().catch(function () {
    setStatus("Session initialization failed.");
  });
}());
"""


def _esc(val: object) -> str:
    return html.escape("" if val is None else str(val), quote=True)


def render_review_html(summary: Mapping[str, JsonValue], *, default_action: str = "approve") -> str:
    """Render SSR HTML shell with every proposal field strictly escaped and zero inline JS/URLs."""
    pid = _esc(summary.get("proposal_id"))
    kind = _esc(summary.get("kind"))
    status = _esc(summary.get("status"))
    risk = _esc(summary.get("risk_level"))
    rev = _esc(summary.get("subject_revision"))
    reason = _esc(summary.get("reason"))
    raw_targets = summary.get("targets")
    targets_list = raw_targets if isinstance(raw_targets, list) else []
    target_items: list[str] = []
    for item in targets_list:
        if isinstance(item, Mapping):
            rel = _esc(item.get("rel_path"))
            slc = _esc(item.get("slice_id"))
            target_items.append(f"<li><code>{rel}</code> (slice <code>{slc}</code>)</li>")
    targets_html = "\n        ".join(target_items) if target_items else "<li>None</li>"
    options_html = "\n".join(
        f'        <option value="{act}"{" selected" if act == default_action else ""}>{act}</option>'
        for act in ("approve", "reject", "apply", "rollback")
    )
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '  <meta charset="utf-8">\n'
        "  <title>Super Brain Proposal Review</title>\n"
        '  <link rel="stylesheet" href="/assets/review.css">\n'
        "</head>\n"
        "<body>\n"
        '  <main class="card">\n'
        "    <h1>Proposal Review</h1>\n"
        f'    <p>Proposal: <span class="badge">{pid}</span> | Kind: <span class="badge">{kind}</span> | '
        f'Status: <span class="badge">{status}</span></p>\n'
        f'    <p>Risk: <span class="badge">{risk}</span> | Revision: <span class="badge">{rev}</span></p>\n'
        f"    <p>Reason: {reason}</p>\n"
        "    <h2>Targets</h2>\n"
        "    <ul>\n"
        f"        {targets_html}\n"
        "    </ul>\n"
        '    <div>\n'
        '      <label for="action-select">Action:</label>\n'
        '      <select id="action-select">\n'
        f"{options_html}\n"
        "      </select>\n"
        '      <label for="signer-select">Passkey Signer:</label>\n'
        '      <select id="signer-select"></select>\n'
        '      <button id="submit-btn" type="button" disabled>Sign &amp; Submit Passkey</button>\n'
        "    </div>\n"
        '    <p id="status">Initializing review session...</p>\n'
        '    <pre id="details"></pre>\n'
        "  </main>\n"
        '  <script src="/assets/review.js"></script>\n'
        "</body>\n"
        "</html>\n"
    )
