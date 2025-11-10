// webauthn-client.js — suporte extra a Samsung Pass no registro + no-store, credentials: 'include', timeout 120s e fallback de login + LOG DO CLIENTE
(function () {
  const $ = (sel) => document.querySelector(sel);
  const statusEl = $('#status');
  const emailEl  = $('#email');
  const btnReg   = $('#btnRegister');
  const btnLogin = $('#btnLogin');

  const setStatus = (msg, ok=false) => {
    if (!statusEl) return console.log('[status]', msg);
    statusEl.textContent = msg;
    statusEl.className = ok ? 'ok' : 'error';
  };

  // Detecta ambiente Samsung/Samsung Internet
  function isSamsungLike() {
    const ua = (navigator.userAgent || '').toLowerCase();
    return /samsungbrowser|sm-\w+/i.test(ua);
  }

  // ---- helpers base64url <-> ArrayBuffer ----
  function b64uToArrayBuffer(b64url) {
    const s = String(b64url || '');
    if (!s) return new ArrayBuffer(0);
    const b64 = s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length/4)*4, '=');
    const raw = atob(b64);
    const buf = new ArrayBuffer(raw.length);
    const view = new Uint8Array(buf);
    for (let i=0; i<raw.length; i++) view[i] = raw.charCodeAt(i);
    return buf;
  }
  function arrayBufferToB64u(buf) {
    const bytes = new Uint8Array(buf || []);
    let bin = '';
    for (let i=0;i<bytes.length;i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  }

  // fetch JSON com cookie de sessão + SEM CACHE
  async function fetchJSON(url, opts = {}) {
    const finalOpts = {
      credentials: 'include',
      cache: 'no-store',
      ...opts
    };
    const res = await fetch(url, finalOpts);
    const text = await res.text();
    let json;
    try { json = JSON.parse(text); } catch {
      throw new Error(`Resposta não-JSON de ${url}: ${text.slice(0,200)}`);
    }
    if (!res.ok) {
      const msg = json?.error || json?.mensagem || `HTTP ${res.status}`;
      throw new Error(msg);
    }
    return json;
  }

  // ---- logger do cliente (envia para webauthn_client_log.php) ----
  function clientLog(stage, data = {}) {
    try {
      const payload = {
        stage,
        email: (emailEl?.value || '').trim().toLowerCase() || null,
        ua: navigator.userAgent,
        ts: Date.now(),
        ...data,
      };
      const body = JSON.stringify(payload);
      const blob = new Blob([body], { type: 'application/json' });

      if (navigator.sendBeacon) {
        navigator.sendBeacon('webauthn_client_log.php', blob);
      } else {
        fetch('webauthn_client_log.php', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body,
          keepalive: true,
          credentials: 'include',
          cache: 'no-store',
        });
      }
    } catch (_) {}
  }

  // ===== REGISTRO =====
  async function doRegister() {
    try {
      if (!window.PublicKeyCredential) {
        return setStatus('Seu navegador não suporta Passkeys/WebAuthn.', false);
      }
      const email = (emailEl?.value || '').trim().toLowerCase();
      if (!email) return setStatus('Informe seu e-mail.', false);

      if (btnReg) btnReg.disabled = true;
      if (btnLogin) btnLogin.disabled = true;
      setStatus('Gerando options de registro...');
      clientLog('REG_OPT_REQ');

      // 1) Pede options ao servidor
      const options = await fetchJSON('register_options.php', {
        method: 'POST',
        headers: { 'Content-Type':'application/x-www-form-urlencoded' },
        body: `email=${encodeURIComponent(email)}`
      });
      clientLog('REG_OPT_OK');

      // 2) Converte binários
      options.publicKey.challenge = b64uToArrayBuffer(options.publicKey.challenge);
      if (options.publicKey.user && typeof options.publicKey.user.id === 'string') {
        options.publicKey.user.id = b64uToArrayBuffer(options.publicKey.user.id);
      }

      // 3) Ajustes seguros e timeout maior
      const pk = options.publicKey;
      pk.timeout = 120000;
      pk.attestation = pk.attestation || 'none';
      pk.authenticatorSelection = {
        ...pk.authenticatorSelection,
        residentKey: pk.authenticatorSelection?.residentKey || 'preferred',
        requireResidentKey: false
      };
      // (mantemos authenticatorAttachment se vier do servidor)

      // 4) WebAuthn create() com fallback "Samsung Pass"
      setStatus('Aguardando biometria/PIN para criar sua Passkey...');
      clientLog('REG_CREATE_TRY');
      let cred;
      try {
        cred = await navigator.credentials.create(options);
      } catch (e) {
        clientLog('REG_CREATE_ERR', { name: e?.name, message: e?.message });
        // Alguns Samsung/Samsung Internet falham com erro genérico do Credential Manager.
        const msg = String(e?.message || '').toLowerCase();
        const samsungQuirk = isSamsungLike() &&
          (e?.name === 'UnknownError' ||
           e?.name === 'NotAllowedError' ||
           msg.includes('credential manager'));
        if (!samsungQuirk) throw e;

        // Fallback: remove o authenticatorAttachment e tenta de novo,
        // permitindo que o SO escolha o provedor (Samsung Pass/Google).
        const opt2 = { publicKey: { ...pk } };
        if (opt2.publicKey.authenticatorSelection) {
          delete opt2.publicKey.authenticatorSelection.authenticatorAttachment;
        }
        setStatus('Tentando novamente (compatibilidade Samsung Pass)…');
        clientLog('REG_CREATE_TRY2');
        cred = await navigator.credentials.create(opt2);
        if (!cred) throw e; // se continuar nulo, propaga erro original
      }

      if (!cred) throw new Error('Criação de credencial cancelada.');
      clientLog('REG_CREATE_OK', { id_len: cred?.rawId?.byteLength || null });

      // 5) Payload pro servidor
      const attResp = cred.response;
      const payload = {
        id: cred.id,
        rawId: arrayBufferToB64u(cred.rawId),
        type: cred.type,
        response: {
          clientDataJSON: arrayBufferToB64u(attResp.clientDataJSON),
          attestationObject: arrayBufferToB64u(attResp.attestationObject)
        }
      };

      // 6) Salva no servidor
      setStatus('Confirmando registro no servidor...');
      await fetchJSON('register.php', {
        method: 'POST',
        headers: { 'Content-Type':'application/json' },
        body: JSON.stringify(payload)
      });
      clientLog('REG_SAVE_OK');

      setStatus('Passkey registrada com sucesso! Entrando…', true);
      await new Promise(r => setTimeout(r, 800));
      await doLogin();
    } catch (err) {
      clientLog('REG_ERR', { name: err?.name, message: err?.message });
      const name = err?.name || '';
      if (name === 'NotAllowedError') {
        setStatus('Ação cancelada pelo usuário ou tempo esgotado.');
      } else {
        setStatus(`Erro no registro: ${err.message || err}`, false);
      }
      console.error(err);
    } finally {
      if (btnReg) btnReg.disabled = false;
      if (btnLogin) btnLogin.disabled = false;
    }
  }

  // ===== LOGIN (com fallback) =====
  async function doLogin() {
    try {
      if (!window.PublicKeyCredential) {
        return setStatus('Seu navegador não suporta Passkeys/WebAuthn.', false);
      }
      const email = (emailEl?.value || '').trim().toLowerCase();
      if (!email) return setStatus('Informe seu e-mail.', false);

      if (btnReg) btnReg.disabled = true;
      if (btnLogin) btnLogin.disabled = true;
      setStatus('Gerando options de login...');
      clientLog('LOGIN_OPT_REQ');

      // 1) Pede options ao servidor
      const options = await fetchJSON('login_options.php', {
        method: 'POST',
        headers: { 'Content-Type':'application/x-www-form-urlencoded' },
        body: `email=${encodeURIComponent(email)}`
      });
      clientLog('LOGIN_OPT_OK', {
        haveCreds: Array.isArray(options.publicKey?.allowCredentials) ? options.publicKey.allowCredentials.length : 0
      });

      // 2) Converte challenge e allowCredentials[].id
      options.publicKey.challenge = b64uToArrayBuffer(options.publicKey.challenge);
      if (Array.isArray(options.publicKey.allowCredentials)) {
        options.publicKey.allowCredentials = options.publicKey.allowCredentials.map((c) => ({
          ...c,
          id: b64uToArrayBuffer(c.id)
        }));
      }
      // 3) Timeout maior
      options.publicKey.timeout = 120000;

      // 4) WebAuthn get() — tentativa A (com allowCredentials)
      setStatus('Aguardando biometria/PIN para Entrar...');
      clientLog('LOGIN_GET_TRY', {
        allowCreds: !!(options.publicKey?.allowCredentials && options.publicKey.allowCredentials.length)
      });
      try {
        const assertion = await navigator.credentials.get(options);
        clientLog('LOGIN_GET_OK', { rawId_len: assertion?.rawId?.byteLength || null });
        await finishLogin(assertion);
        return;
      } catch (e) {
        clientLog('LOGIN_GET_ERR', { name: e?.name, message: e?.message });
        // Se foi cancelado/timeout, tentamos descoberta (sem allowCredentials) antes de desistir
        if (e?.name !== 'NotAllowedError') throw e;
      }

      // 5) Tentativa B (fallback): sem allowCredentials → permite descoberta de passkey
      clientLog('LOGIN_FALLBACK_TRY');
      try {
        const optionsFallback = {
          publicKey: { ...options.publicKey, allowCredentials: [] }
        };
        const assertion2 = await navigator.credentials.get(optionsFallback);
        clientLog('LOGIN_FALLBACK_OK', { rawId_len: assertion2?.rawId?.byteLength || null });
        await finishLogin(assertion2);
        return;
      } catch (e2) {
        clientLog('LOGIN_FALLBACK_ERR', { name: e2?.name, message: e2?.message });
        if (e2?.name === 'NotAllowedError') {
          setStatus('Ação cancelada ou nenhuma credencial disponível no dispositivo.');
        } else {
          console.error(e2);
          setStatus('Erro ao obter credencial (fallback).', false);
        }
      }
    } catch (err) {
      clientLog('LOGIN_ERR', { name: err?.name, message: err?.message });
      const name = err?.name || '';
      if (name === 'NotAllowedError') {
        setStatus('Ação cancelada pelo usuário ou tempo esgotado.');
      } else {
        setStatus(`Erro no login: ${err.message || err}`, false);
      }
      console.error(err);
    } finally {
      if (btnReg) btnReg.disabled = false;
      if (btnLogin) btnLogin.disabled = false;
    }
  }

  async function finishLogin(assertion) {
    if (!assertion) throw new Error('Login cancelado.');
    const authResp = assertion.response;
    const payload = {
      id: assertion.id,
      rawId: arrayBufferToB64u(assertion.rawId),
      type: assertion.type,
      response: {
        clientDataJSON:    arrayBufferToB64u(authResp.clientDataJSON),
        authenticatorData: arrayBufferToB64u(authResp.authenticatorData),
        signature:         arrayBufferToB64u(authResp.signature),
        userHandle:        authResp.userHandle ? arrayBufferToB64u(authResp.userHandle) : null
      }
    };

    setStatus('Validando login no servidor...');
    const loginRes = await fetchJSON('login.php', {
      method: 'POST',
      headers: { 'Content-Type':'application/json' },
      body: JSON.stringify(payload)
    });
    clientLog('LOGIN_FINISH_OK', { user_present: !!loginRes?.user });

    if (loginRes && loginRes.user) {
      try {
        localStorage.setItem('nome_usuario', loginRes.user.nome_usuario || loginRes.user.nome || '');
        localStorage.setItem('nome_pessoa',  loginRes.user.nome || '');
        localStorage.setItem('email',        loginRes.user.email || '');
      } catch (_) {}
    }

    setStatus('Login ok! Redirecionando...', true);
    location.href = 'index.html';
  }

  // Liga eventos (mantém seus IDs)
  window.addEventListener('DOMContentLoaded', () => {
    if (btnReg)   btnReg.addEventListener('click', doRegister);
    if (btnLogin) btnLogin.addEventListener('click', doLogin);
  });
})();
