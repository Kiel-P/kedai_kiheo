// Responsive converter with:
// - VLESS default cipher set to "auto"
// - Domain additions now prefixed (didepan host & sni)
// - Persistent parsed state so custom name / domains can be applied after convert
// - No console output; feedback shown in UI

(function(){
  // --- Helpers ---
  function qsToObj(search) {
    if (!search) return {};
    const params = {};
    new URLSearchParams(search.replace(/^\?/, '')).forEach((v, k) => params[k] = v);
    return params;
  }
  function safeDecode(s){ try { return decodeURIComponent(s||''); } catch(e){ return s||''; } }
  function clone(obj){ return JSON.parse(JSON.stringify(obj)); }

  // --- Parsers ---
  function tryParseTrojanWithURL(u) {
    const params = qsToObj(u.search);
    const name = safeDecode((u.hash || '').replace(/^#/, '')) || params.remarks || '';
    const server = u.hostname;
    const port = u.port || 443;
    const security = params.security || '';
    const type = params.type || '';
    const sni = params.sni || params.host || '';
    const path = params.path ? safeDecode(params.path) : (params.p && safeDecode(params.p)) || '/';
    const network = type || (params.net || params.network) || (type === 'ws' ? 'ws' : 'tcp');
    const password = safeDecode(u.username || u.password || params.password || '');
    const obj = {
      name: name || `${server}:${port} (trojan)`,
      server,
      port: Number(port),
      type: 'trojan',
      password: password || '',
      'skip-cert-verify': /tls/i.test(security),
      network: network || undefined,
      udp: true
    };
    if (sni) obj.sni = sni;
    if (network === 'ws' || network === 'wss') {
      obj['ws-opts'] = { path: path || '/', headers: {} };
      if (params.host || sni) obj['ws-opts'].headers.Host = params.host || sni;
    }
    return obj;
  }
  function tryParseVLESSWithURL(u) {
    const params = qsToObj(u.search);
    const name = safeDecode((u.hash || '').replace(/^#/, '')) || params.remarks || '';
    const uuid = safeDecode(u.username || '') || params.id || params.uuid || '';
    const server = u.hostname;
    const port = u.port || 443;
    const security = params.security || params.tls || params.secure || '';
    const network = params.type || params.net || params.network || 'tcp';
    const path = params.path ? safeDecode(params.path) : '/';
    const sni = params.sni || params.host || params.hostname || '';
    const obj = {
      name: name || `${server}:${port} (vless)`,
      server,
      port: Number(port),
      type: 'vless',
      uuid: uuid || '',
      cipher: params.encryption || 'auto', // default to 'auto'
    };
    if (/tls/i.test(security) || params.tls === '1' || params.tls === 'true') {
      obj.tls = true;
      obj['skip-cert-verify'] = true;
    }
    if (sni) obj.sni = sni;
    if (network === 'ws') {
      obj.network = 'ws';
      obj['ws-opts'] = { path: path || '/', headers: {} };
      if (params.host || sni) obj['ws-opts'].headers.Host = params.host || sni;
    } else if (network === 'grpc') {
      obj.network = 'grpc';
      if (params.serviceName) obj['grpc-opts'] = { 'grpc-service-name': params.serviceName };
    } else {
      obj.network = network;
    }
    return obj;
  }
  function tryParseTrojanFallback(line) {
    const m = line.match(/^trojan:\/\/([^@]+)@([^:\/?#]+)(?::(\d+))?(?:\?([^#]*))?(?:#(.*))?$/i);
    if (!m) return null;
    const password = safeDecode(m[1] || '');
    const server = m[2];
    const port = m[3] || 443;
    const search = m[4] ? ('?' + m[4]) : '';
    const hash = m[5] ? ('#' + m[5]) : '';
    try {
      return tryParseTrojanWithURL(new URL(`trojan://${encodeURIComponent(password)}@${server}:${port}${search}${hash}`));
    } catch (e) {
      return {
        name: (m[5] || `${server}:${port} (trojan)`),
        server,
        port: Number(port),
        type: 'trojan',
        password,
        'skip-cert-verify': /security= ?tls/i.test(m[4] || ''),
        network: /type= ?ws/i.test(m[4] || '') ? 'ws' : 'tcp',
        udp: true
      };
    }
  }
  function tryParseVLESSFallback(line) {
    const m = line.match(/^vless:\/\/([^@]+)@([^:\/?#]+)(?::(\d+))?(?:\?([^#]*))?(?:#(.*))?$/i);
    if (!m) return null;
    const uuid = safeDecode(m[1] || '');
    const server = m[2];
    const port = m[3] || 443;
    const search = m[4] ? ('?' + m[4]) : '';
    const hash = m[5] ? ('#' + m[5]) : '';
    try {
      return tryParseVLESSWithURL(new URL(`vless://${encodeURIComponent(uuid)}@${server}:${port}${search}${hash}`));
    } catch (e) {
      return {
        name: (m[5] || `${server}:${port} (vless)`),
        server,
        port: Number(port),
        type: 'vless',
        uuid,
        cipher: 'auto'
      };
    }
  }
  function base64DecodeSafe(b64) {
    try {
      b64 = b64.replace(/-/g, '+').replace(/_/g, '/');
      while (b64.length % 4) b64 += '=';
      return atob(b64);
    } catch (e) {
      return null;
    }
  }
  function tryParseVMess(line) {
    try {
      const after = line.replace(/^vmess:\/\//i, '').trim();
      const hashIndex = after.indexOf('#');
      const base64 = hashIndex >= 0 ? after.slice(0, hashIndex) : after;
      const base64Clean = base64.replace(/\s+/g, '');
      const jsonText = base64DecodeSafe(base64Clean);
      if (!jsonText) return null;
      const j = JSON.parse(jsonText);
      const name = j.ps || (hashIndex >= 0 ? safeDecode(after.slice(hashIndex + 1)) : '');
      const server = j.add || '';
      const port = j.port || 443;
      const uuid = j.id || j.uuid || '';
      const alterId = j.aid != null ? Number(j.aid) : 0;
      const net = j.net || j.type || 'tcp';
      const path = j.path || '/';
      const host = j.host || '';
      const tls = (typeof j.tls === 'string' ? j.tls.toLowerCase() === 'tls' : !!j.tls);
      const obj = {
        name: name || `${server}:${port} (vmess)`,
        server,
        port: Number(port),
        type: 'vmess',
        uuid: uuid || '',
        alterId: alterId,
        cipher: j.cipher || 'auto'
      };
      if (tls) {
        obj.tls = true;
        obj['skip-cert-verify'] = true;
      }
      if (net === 'ws') {
        obj.network = 'ws';
        obj['ws-opts'] = { path: path || '/', headers: {} };
        if (host) obj['ws-opts'].headers.Host = host;
      } else {
        obj.network = net;
      }
      return obj;
    } catch (e) {
      return null;
    }
  }

  // --- YAML serializer ---
  function yamlSafeString(s) {
    if (s === undefined || s === null) return "''";
    s = String(s);
    if (/[:#\n]/.test(s) || /^\s|\s$/.test(s)) {
      return JSON.stringify(s);
    }
    return s;
  }
  function toYaml(proxies) {
    const lines = ['proxies:'];
    proxies.forEach(p => {
      lines.push('  - name: ' + yamlSafeString(p.name));
      lines.push('    server: ' + yamlSafeString(p.server));
      lines.push('    port: ' + (p.port || 0));
      lines.push('    type: ' + (p.type || ''));
      if (p.type === 'trojan') {
        lines.push('    password: ' + yamlSafeString(p.password || ''));
      } else if (p.type === 'vless') {
        lines.push('    uuid: ' + yamlSafeString(p.uuid || ''));
        if (p.cipher) lines.push('    cipher: ' + yamlSafeString(p.cipher));
      } else if (p.type === 'vmess') {
        lines.push('    uuid: ' + yamlSafeString(p.uuid || ''));
        if (p.alterId !== undefined) lines.push('    alterId: ' + (p.alterId || 0));
        if (p.cipher) lines.push('    cipher: ' + yamlSafeString(p.cipher));
      }
      if (p['skip-cert-verify'] !== undefined) lines.push('    skip-cert-verify: ' + (p['skip-cert-verify'] ? 'true' : 'false'));
      if (p.tls) lines.push('    tls: true');
      if (p.network) lines.push('    network: ' + yamlSafeString(p.network));
      if (p.udp !== undefined) lines.push('    udp: ' + (p.udp ? 'true' : 'false'));
      if (p.sni) lines.push('    sni: ' + yamlSafeString(p.sni));
      if (p['ws-opts']) {
        lines.push('    ws-opts:');
        if (p['ws-opts'].path) lines.push('      path: ' + yamlSafeString(p['ws-opts'].path));
        if (p['ws-opts'].headers) {
          lines.push('      headers:');
          Object.keys(p['ws-opts'].headers).forEach(h => {
            lines.push('        ' + h + ': ' + yamlSafeString(p['ws-opts'].headers[h]));
          });
        }
      }
    });
    return lines.join('\n');
  }

  // --- Domain addition helper (prefix) ---
  // Prepend domainPart to an existing host-like string if not already present.
  function prependDomainIfNeeded(original, domainPart) {
    if (!domainPart) return original || '';
    const cleaned = String(domainPart || '').trim();
    if (!cleaned) return original || '';
    if (!original) return cleaned;
    // If original already starts with cleaned (exact) or cleaned + '.', keep original
    if (original === cleaned) return original;
    if (original.startsWith(cleaned + '.') || original.startsWith(cleaned)) return original;
    return `${cleaned}.${original}`;
  }

  // --- Convert all lines into proxies (returns {proxies, errors}) ---
  function convertAll(text) {
    const lines = text.split(/\r?\n/).map((l, i) => ({ raw: l, line: i + 1 })).filter(x => x.raw && x.raw.trim());
    const proxies = [];
    const errors = [];
    lines.forEach(item => {
      const line = item.raw.trim();
      try {
        if (/^trojan:\/\//i.test(line)) {
          let p = null;
          try {
            p = tryParseTrojanWithURL(new URL(line));
          } catch (e) {
            p = tryParseTrojanFallback(line);
          }
          if (p) proxies.push(p);
          else errors.push({ line: item.line, text: line, err: 'Failed to parse trojan' });
        } else if (/^vless:\/\//i.test(line)) {
          let p = null;
          try {
            p = tryParseVLESSWithURL(new URL(line));
          } catch (e) {
            p = tryParseVLESSFallback(line);
          }
          if (p) proxies.push(p);
          else errors.push({ line: item.line, text: line, err: 'Failed to parse vless' });
        } else if (/^vmess:\/\//i.test(line)) {
          const p = tryParseVMess(line);
          if (p) proxies.push(p);
          else errors.push({ line: item.line, text: line, err: 'Failed to parse vmess' });
        } else {
          errors.push({ line: item.line, text: line, err: 'Unknown or unsupported scheme' });
        }
      } catch (e) {
        errors.push({ line: item.line, text: line, err: e && e.message ? e.message : String(e) });
      }
    });
    return { proxies, errors };
  }

  // --- State ---
  let parsedProxies = []; // original parsed proxies (not mutated)
  let lastRenderedFinal = []; // final proxies used to render YAML
  let lastSuggestedFilename = 'proxies.yaml';

  // --- filename helper ---
  function makeSafeFilename(name) {
    if (!name) return 'proxies';
    let s = String(name).trim();
    // remove surrounding quotes/hashes if present
    s = s.replace(/^"+|"+$/g,'').replace(/^'+|'+$/g,'').replace(/^#+|#+$/g,'');
    // remove protocol if any
    s = s.replace(/^[a-z]+:\/\//i, '');
    // replace illegal filesystem chars
    s = s.replace(/[\/\\\?\%\*\:\|"<>]/g, '-');
    // replace spaces with underscores
    s = s.replace(/\s+/g, '_');
    // collapse multiple underscores/dashes
    s = s.replace(/_+/g,'_').replace(/\-+/g,'-');
    // limit length
    if (s.length > 120) s = s.slice(0,120);
    // fallback
    if (!s) return 'proxies';
    return s;
  }

  // --- UI wiring ---
  document.addEventListener('DOMContentLoaded', () => {
    const input = document.getElementById('inputLinks');
    const convertBtn = document.getElementById('convertBtn');
    const output = document.getElementById('outputYaml');
    const copyBtn = document.getElementById('copyBtn');
    const downloadBtn = document.getElementById('downloadBtn');
    const messages = document.getElementById('messages');
    const fillBtn = document.getElementById('fillExampleBtn');
    const clearBtn = document.getElementById('clearBtn');

    const useCustomNameCheckbox = document.getElementById('useCustomName');
    const customNameInput = document.getElementById('customName');

    const addDomainBtn = document.getElementById('addDomainBtn');
    const clearDomainsBtn = document.getElementById('clearDomainsBtn');
    const domainList = document.getElementById('domainList');

    function setMessage(html, isError) {
      messages.innerHTML = html || '';
      messages.style.color = isError ? 'var(--danger)' : 'var(--muted)';
    }

    // Domain UI helpers
    function createDomainRow(domain='') {
      const row = document.createElement('div');
      row.className = 'domain-row';
      const inpDomain = document.createElement('input');
      inpDomain.type = 'text';
      inpDomain.placeholder = 'Wildcard to prefix (mis. kiheo.my.id)';
      inpDomain.value = domain;
      const btnRemove = document.createElement('button');
      btnRemove.type = 'button';
      btnRemove.textContent = 'Hapus';
      btnRemove.className = 'muted small';
      btnRemove.addEventListener('click', () => {
        row.remove();
        if (parsedProxies.length) renderYaml();
      });
      inpDomain.addEventListener('input', () => {
        if (parsedProxies.length) renderYaml();
      });
      row.appendChild(inpDomain);
      row.appendChild(btnRemove);
      return row;
    }

    addDomainBtn.addEventListener('click', () => {
      domainList.appendChild(createDomainRow());
      setMessage('Domain entry ditambahkan.', false);
    });

    clearDomainsBtn.addEventListener('click', () => {
      domainList.innerHTML = '';
      setMessage('Semua domain dibersihkan.', false);
      if (parsedProxies.length) renderYaml();
    });

    fillBtn.addEventListener('click', () => {
      input.value = `trojan://enAsoMwPVZOd6SduHFQ@bug:443?path=%2Ftrojan&security=tls&host=kiheo.my.id&type=ws&sni=kiheo.my.id#Biznet`;
      domainList.innerHTML = '';
      domainList.appendChild(createDomainRow('kiheo.my.id'));
      setMessage('Contoh dimasukkan. Tekan Convert untuk melihat hasil.', false);
      input.focus();
    });

    clearBtn.addEventListener('click', () => {
      input.value = '';
      output.value = '';
      domainList.innerHTML = '';
      useCustomNameCheckbox.checked = false;
      customNameInput.value = '';
      parsedProxies = [];
      lastRenderedFinal = [];
      lastSuggestedFilename = 'proxies.yaml';
      setMessage('Input, output, dan domain dibersihkan.', false);
      input.focus();
    });

    // When custom name inputs change, re-render YAML if already converted
    useCustomNameCheckbox.addEventListener('change', () => {
      if (parsedProxies.length) renderYaml();
    });
    customNameInput.addEventListener('input', () => {
      if (parsedProxies.length) renderYaml();
    });

    // Render YAML from parsedProxies + current UI options
    function renderYaml() {
      if (!parsedProxies || !parsedProxies.length) {
        output.value = '';
        lastRenderedFinal = [];
        lastSuggestedFilename = 'proxies.yaml';
        return;
      }
      // gather domain parts
      const domainRows = Array.from(domainList.querySelectorAll('.domain-row input[type="text"]'));
      const domainParts = domainRows.map(i => (i.value || '').trim()).filter(Boolean);

      // Build proxy list to output
      const final = [];
      // for each parsed proxy, if domainParts provided produce one proxy per domainPart (modified sni/host)
      parsedProxies.forEach((orig, idx) => {
        if (domainParts.length === 0) {
          final.push(clone(orig));
        } else {
          domainParts.forEach(dp => {
            const p = clone(orig);
            // modify sni by prefixing domain
            if (p.sni) p.sni = prependDomainIfNeeded(p.sni, dp);
            // modify ws host header if exists by prefixing domain
            if (p['ws-opts'] && p['ws-opts'].headers && p['ws-opts'].headers.Host) {
              p['ws-opts'].headers.Host = prependDomainIfNeeded(p['ws-opts'].headers.Host, dp);
            }
            // modify name to indicate domain
            p.name = `${orig.name} - ${dp}`;
            final.push(p);
          });
        }
      });

      // apply custom name override if requested
      if (useCustomNameCheckbox.checked) {
        const cn = (customNameInput.value || '').trim();
        if (cn) {
          // ensure unique names by appending index when multiple
          if (final.length > 1) {
            final.forEach((p, i) => {
              p.name = `${cn} ${i+1}`;
            });
          } else {
            final[0].name = cn;
          }
        }
      }

      output.value = toYaml(final);
      lastRenderedFinal = final;

      // determine suggested filename for download
      let suggestedBase = 'proxies';
      if (final.length === 1) {
        suggestedBase = makeSafeFilename(final[0].name) || 'proxy';
      } else {
        // prefer custom name if used
        if (useCustomNameCheckbox.checked) {
          const cn = (customNameInput.value || '').trim();
          if (cn) suggestedBase = makeSafeFilename(cn);
        } else {
          // fallback to generic 'proxies'
          suggestedBase = 'proxies';
        }
      }
      lastSuggestedFilename = `${suggestedBase}.yaml`;
    }

    convertBtn.addEventListener('click', () => {
      setMessage('', false);
      output.value = '';
      const text = input.value;
      if (!text || !text.trim()) {
        setMessage('Masukkan minimal satu link sebelum Convert.', true);
        return;
      }
      const { proxies, errors } = convertAll(text);
      if (proxies.length === 0) {
        const errMsg = `Tidak ada proxy valid. ${errors.length} baris gagal. Contoh: ${errors.slice(0,5).map(e=>'Baris '+e.line+': '+e.err).join(' | ')}`;
        setMessage(errMsg, true);
        parsedProxies = [];
        return;
      }
      parsedProxies = proxies.map(p => clone(p)); // store originals
      renderYaml();
      let msg = `Sukses: ${proxies.length} proxy dikonversi.`;
      if (errors.length) msg += ` Namun ${errors.length} baris gagal. Contoh: ${errors.slice(0,5).map(e=>'Baris '+e.line+': '+e.err).join(' | ')}`;
      if (domainList.querySelectorAll('.domain-row').length) msg += ` Domain additions diterapkan.`;
      setMessage(msg, errors.length > 0);
    });

    copyBtn.addEventListener('click', async () => {
      if (!output.value) {
        setMessage('Tidak ada YAML untuk disalin.', true);
        return;
      }
      try {
        await navigator.clipboard.writeText(output.value);
        setMessage('YAML disalin ke clipboard.', false);
      } catch (e) {
        setMessage('Gagal menyalin. Silakan salin manual dari textarea.', true);
      }
    });

    downloadBtn.addEventListener('click', () => {
      if (!output.value) {
        setMessage('Tidak ada YAML untuk diunduh.', true);
        return;
      }
      // ensure filename is up-to-date by calling renderYaml (if parsedProxies exist)
      if (parsedProxies.length) renderYaml();

      const blob = new Blob([output.value], { type: 'text/yaml;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      // KUNCI: gunakan suggested filename yang dihasilkan saat renderYaml
      a.download = lastSuggestedFilename || 'proxies.yaml';
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      setMessage(`File ${a.download} siap diunduh.`, false);
    });
  });
})();