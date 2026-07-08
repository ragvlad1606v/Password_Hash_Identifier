(() => {
  'use strict';

  // ---------------------------------------------------------------
  // Signature patterns.
  // Confidence is heuristic: prefix-tagged formats (bcrypt, crypt,
  // LDAP, framework-specific) are near-certain. Bare hex/base64
  // digests are ambiguous by nature, since many algorithms share a
  // length, so several candidates split the confidence.
  // ---------------------------------------------------------------

  const HEX = /^[a-fA-F0-9]+$/;
  const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;

  const PREFIX_RULES = [
    { test: h => /^\$2[aby]?\$\d{2}\$/.test(h), name: 'bcrypt', conf: 0.98,
      desc: 'Adaptive password hash built on Blowfish. The cost factor is embedded in the string itself, so it stays slow to brute-force even as hardware improves.',
      tags: ['password hash', 'salted', 'adaptive'] },
    { test: h => /^\$argon2(id|i|d)\$/.test(h), name: 'Argon2', conf: 0.98,
      desc: 'Winner of the 2015 Password Hashing Competition. Tunable for memory, time, and parallelism cost, which makes GPU cracking especially expensive.',
      tags: ['password hash', 'salted', 'memory-hard'] },
    { test: h => /^\$1\$/.test(h), name: 'MD5 crypt (Unix)', conf: 0.95,
      desc: 'Traditional Unix /etc/shadow format from the 1990s. Salted, but built on MD5, which is now considered weak for password storage.',
      tags: ['password hash', 'salted', 'legacy'] },
    { test: h => /^\$5\$/.test(h), name: 'SHA-256 crypt (Unix)', conf: 0.95,
      desc: 'glibc crypt() variant using SHA-256 with a configurable round count, commonly seen in modern /etc/shadow entries.',
      tags: ['password hash', 'salted'] },
    { test: h => /^\$6\$/.test(h), name: 'SHA-512 crypt (Unix)', conf: 0.95,
      desc: 'The current default for /etc/shadow on most Linux distributions. Same design as $5$ but with a wider internal hash.',
      tags: ['password hash', 'salted'] },
    { test: h => /^\$P\$/.test(h) || /^\$H\$/.test(h), name: 'phpBB / WordPress (phpass)', conf: 0.92,
      desc: 'Portable PHP password hashing framework used by WordPress and older phpBB installs. Wraps repeated MD5 rounds.',
      tags: ['password hash', 'salted', 'CMS'] },
    { test: h => /^\$S\$/.test(h), name: 'Drupal 7', conf: 0.92,
      desc: 'Drupal 7\u2019s password format, a phpass variant using SHA-512 internally.',
      tags: ['password hash', 'salted', 'CMS'] },
    { test: h => /^\{SSHA\}/.test(h), name: 'SSHA (salted SHA-1, LDAP)', conf: 0.95,
      desc: 'Salted SHA-1 as stored by LDAP directories. The salt is appended to the digest before base64 encoding.',
      tags: ['LDAP', 'salted'] },
    { test: h => /^\{SHA\}/.test(h), name: 'SHA-1 (LDAP)', conf: 0.93,
      desc: 'Base64-encoded, unsalted SHA-1 as used in older LDAP userPassword fields.',
      tags: ['LDAP'] },
    { test: h => /^sha1\$.+\$[a-f0-9]{40}$/i.test(h), name: 'Django (SHA-1, salted)', conf: 0.95,
      desc: 'Legacy Django password format: algorithm, salt, and digest joined with $.',
      tags: ['password hash', 'salted', 'framework'] },
    { test: h => /^pbkdf2_sha256\$/.test(h), name: 'Django (PBKDF2-SHA256)', conf: 0.96,
      desc: 'Default Django password format since 1.4: iteration count, salt, and digest joined with $.',
      tags: ['password hash', 'salted', 'framework'] },
    { test: h => /^\*[A-F0-9]{40}$/.test(h), name: 'MySQL 4.1+ / 5.x', conf: 0.94,
      desc: 'A leading asterisk followed by an uppercase SHA-1 digest, the format MySQL has used for PASSWORD() since 4.1.',
      tags: ['database'] },
  ];

  function analyze(raw) {
    const h = raw.trim();
    if (!h) return [];

    for (const rule of PREFIX_RULES) {
      if (rule.test(h)) {
        return [{ name: rule.name, confidence: rule.conf, desc: rule.desc, tags: rule.tags }];
      }
    }

    const len = h.length;
    const results = [];

    if (HEX.test(h)) {
      const upperOnly = h === h.toUpperCase() && /[A-F]/.test(h);

      const byLen = {
        8:  [{ n: 'CRC32', c: 0.85, d: 'A checksum, not a cryptographic hash \u2014 fast, but designed to catch accidental corruption, not tampering.', t: ['checksum'] }],
        16: [
          { n: 'MySQL323', c: 0.55, d: 'Old MySQL PASSWORD() format predating 4.1. Weak, and rarely seen outside legacy databases.', t: ['database', 'legacy'] },
          { n: 'Half MD5 (truncated)', c: 0.3, d: 'Could be the first or last 16 hex characters of an MD5 digest, sometimes used to save storage space.', t: ['truncated'] },
        ],
        32: [
          { n: 'MD5', c: 0.5, d: 'The most common 128-bit digest by far. Broken for collision resistance and unsuitable for passwords, but still everywhere for checksums and cache keys.', t: ['general purpose', 'broken for security'] },
          { n: 'NTLM', c: 0.25, d: 'Windows password hash \u2014 unsalted MD4 of the UTF-16LE password. Identical shape to MD5, so context (Windows/AD source) is the real tell.', t: ['password hash', 'Windows'] },
          { n: 'MD4', c: 0.1, d: 'Predecessor to MD5, largely obsolete outside of being the core of NTLM.', t: ['legacy'] },
          { n: 'LM hash', c: upperOnly ? 0.2 : 0.05, d: 'Ancient Windows LAN Manager hash, split into two 16-byte DES halves. Case-insensitive password handling made it trivially weak.', t: ['password hash', 'Windows', 'legacy'] },
        ],
        40: [
          { n: 'SHA-1', c: 0.75, d: '160-bit digest, once the web\u2019s default. Deprecated for security-critical use since 2017 after practical collisions were demonstrated.', t: ['general purpose', 'broken for security'] },
          { n: 'RIPEMD-160', c: 0.15, d: 'Same output size as SHA-1 but a different design, notably used inside Bitcoin address generation.', t: ['general purpose'] },
          { n: 'HAS-160', c: 0.1, d: 'Korean standard hash function, same digest length as SHA-1.', t: ['general purpose', 'regional standard'] },
        ],
        56: [
          { n: 'SHA-224', c: 0.55, d: 'Truncated variant of SHA-256 with a shorter output.', t: ['general purpose'] },
          { n: 'SHA3-224', c: 0.45, d: 'Keccak-based SHA-3 family member at the 224-bit output size.', t: ['general purpose'] },
        ],
        64: [
          { n: 'SHA-256', c: 0.55, d: 'Current workhorse hash \u2014 used everywhere from TLS certificates to Bitcoin block hashing. No known practical attacks.', t: ['general purpose'] },
          { n: 'SHA3-256', c: 0.2, d: 'Keccak-based SHA-3 at 256 bits, a structurally different design from SHA-2.', t: ['general purpose'] },
          { n: 'BLAKE2s / BLAKE3', c: 0.15, d: 'Modern, fast hash family often used where SHA-2 would otherwise go, but with better performance.', t: ['general purpose'] },
          { n: 'Keccak-256', c: 0.1, d: 'Pre-standardization Keccak variant, notably used for Ethereum address and transaction hashing.', t: ['blockchain'] },
        ],
        96: [
          { n: 'SHA-384', c: 0.65, d: 'Truncated SHA-512 variant, common in TLS cipher suites that want more margin than SHA-256.', t: ['general purpose'] },
          { n: 'SHA3-384', c: 0.35, d: 'Keccak-based SHA-3 at the 384-bit size.', t: ['general purpose'] },
        ],
        128: [
          { n: 'SHA-512', c: 0.55, d: '512-bit member of the SHA-2 family. Slower per-byte on 32-bit hardware but faster on 64-bit systems than SHA-256.', t: ['general purpose'] },
          { n: 'SHA3-512', c: 0.25, d: 'Keccak-based SHA-3 at the largest common output size.', t: ['general purpose'] },
          { n: 'Whirlpool', c: 0.2, d: '512-bit hash built on an AES-like block cipher design, used in some archival and forensic tools.', t: ['general purpose'] },
        ],
      };

      if (byLen[len]) {
        for (const cand of byLen[len]) {
          results.push({ name: cand.n, confidence: cand.c, desc: cand.d, tags: cand.t });
        }
      }
    }

    // Base64-shaped digests (fixed lengths correspond to common bit sizes)
    const looksBase64 = BASE64.test(h) && !HEX.test(h);
    if (results.length === 0 && looksBase64) {
      const base64Lens = {
        24: [{ n: 'MD5 (base64)', c: 0.6, d: '128-bit MD5 digest encoded as base64 instead of hex \u2014 same algorithm, more compact representation.', t: ['general purpose', 'encoding: base64'] }],
        28: [{ n: 'SHA-1 (base64)', c: 0.6, d: '160-bit SHA-1 digest encoded as base64, the form LDAP\u2019s {SHA} scheme uses internally.', t: ['general purpose', 'encoding: base64'] }],
        44: [{ n: 'SHA-256 (base64)', c: 0.6, d: '256-bit SHA-256 digest encoded as base64, common in HTTP Subresource Integrity attributes.', t: ['general purpose', 'encoding: base64'] }],
        88: [{ n: 'SHA-512 (base64)', c: 0.6, d: '512-bit SHA-512 digest encoded as base64.', t: ['general purpose', 'encoding: base64'] }],
      };
      if (base64Lens[len]) {
        for (const cand of base64Lens[len]) {
          results.push({ name: cand.n, confidence: cand.c, desc: cand.d, tags: cand.t });
        }
      }
    }

    return results.sort((a, b) => b.confidence - a.confidence);
  }

  // ---------------------------------------------------------------
  // UI wiring
  // ---------------------------------------------------------------

  const input = document.getElementById('hashInput');
  const meter = document.getElementById('meter');
  const lengthReadout = document.getElementById('lengthReadout');
  const chipLength = document.getElementById('chipLength').querySelector('.chip-val');
  const chipCharset = document.getElementById('chipCharset').querySelector('.chip-val');
  const chipDelim = document.getElementById('chipDelim').querySelector('.chip-val');
  const resultsList = document.getElementById('resultsList');
  const resultsCount = document.getElementById('resultsCount');

  const SEGMENTS = 40;
  const MAX_SCALE = 130; // roughly a SHA-512 hex digest, tallest common case

  // Build the meter segments once.
  for (let i = 0; i < SEGMENTS; i++) {
    const seg = document.createElement('div');
    seg.className = 'meter-seg';
    meter.appendChild(seg);
  }
  const segEls = Array.from(meter.children);

  function describeCharset(h) {
    if (!h) return '—';
    if (/^[a-fA-F0-9]+$/.test(h)) return 'hex';
    if (/^[A-Za-z0-9+/]+={0,2}$/.test(h) && /[a-z]/.test(h) && /[A-Z]/.test(h)) return 'base64';
    if (/^[A-Za-z0-9]+$/.test(h)) return 'alphanumeric';
    return 'mixed / symbols';
  }

  function describeDelim(h) {
    if (!h) return '—';
    if (h.startsWith('$')) return 'modular crypt ($id$)';
    if (h.startsWith('{')) return 'braced scheme ({ID})';
    if (h.startsWith('*')) return 'asterisk-prefixed';
    return 'plain';
  }

  function renderMeter(len) {
    const lit = Math.min(SEGMENTS, Math.round((len / MAX_SCALE) * SEGMENTS));
    segEls.forEach((seg, i) => {
      seg.classList.toggle('lit', i < lit);
      seg.classList.toggle('peak', i === lit - 1);
    });
  }

  function confidenceClass(c) {
    if (c >= 0.8) return 'high';
    if (c >= 0.4) return '';
    return 'low';
  }

  function renderResults(matches, hasInput) {
    resultsList.innerHTML = '';

    if (!hasInput) {
      resultsCount.textContent = '0 found';
      const empty = document.createElement('div');
      empty.className = 'empty-state';
      empty.innerHTML = '<p>Waiting on input. Drop a hash above &mdash; MD5, SHA-family, bcrypt, NTLM, and two dozen others are on file.</p>';
      resultsList.appendChild(empty);
      return;
    }

    if (matches.length === 0) {
      resultsCount.textContent = '0 found';
      const banner = document.createElement('div');
      banner.className = 'no-match-banner';
      banner.textContent = 'No signature on file matches this shape. It may be a non-standard hash, a truncated digest, or plain encoded text.';
      resultsList.appendChild(banner);
      return;
    }

    resultsCount.textContent = `${matches.length} found`;

    matches.forEach((m, i) => {
      const pct = Math.round(m.confidence * 100);
      const cClass = confidenceClass(m.confidence);

      const card = document.createElement('div');
      card.className = 'match';
      card.innerHTML = `
        <div class="match-top">
          <span class="match-name"><span class="rank">${String(i + 1).padStart(2, '0')}</span>${m.name}</span>
          <span class="match-confidence ${cClass}">${pct}% match</span>
        </div>
        <div class="confidence-bar"><div class="confidence-fill ${cClass}" style="width:${pct}%"></div></div>
        <p class="match-desc">${m.desc}</p>
        <div class="match-tags">${m.tags.map(t => `<span class="tag">${t}</span>`).join('')}</div>
      `;
      resultsList.appendChild(card);
    });
  }

  function update() {
    const raw = input.value;
    const trimmed = raw.trim();
    const len = trimmed.length;

    lengthReadout.textContent = `${len} char${len === 1 ? '' : 's'}`;
    lengthReadout.classList.toggle('active', len > 0);
    renderMeter(len);

    chipLength.textContent = len ? String(len) : '—';
    chipCharset.textContent = describeCharset(trimmed);
    chipDelim.textContent = describeDelim(trimmed);

    const matches = analyze(trimmed);
    renderResults(matches, len > 0);
  }

  input.addEventListener('input', update);

  // Initialize meter + empty state on load.
  renderMeter(0);
  update();
})();
