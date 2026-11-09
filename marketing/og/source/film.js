// Spear og:video v4 — a two-block woodcut (black + rubric red) on vellum. One canvas, pure function of t.
(() => {
  const { stage, onSeek, end } = K;
  const W = 1200, H = 630, VEL = '#EFE4C8', BLK = '#141210', RED = '#B8261C';
  const mk = () => { const k = document.createElement('canvas'); k.width = W; k.height = H; return k; };
  const cv = mk(); cv.id = 'cv'; stage.appendChild(cv); const c = cv.getContext('2d');
  const KC = mk(), k = KC.getContext('2d'), RC = mk(), r = RC.getContext('2d');
  const mb = (a) => () => { a |= 0; a = a + 0x6D2B79F5 | 0; let t = Math.imul(a ^ a >>> 15, 1 | a); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; };
  const cl = (x, a = 0, b = 1) => Math.max(a, Math.min(b, x));

  // ---------- paper and "poor inking" textures
  const vellum = (() => { const q = mk(), x = q.getContext('2d'); x.fillStyle = VEL; x.fillRect(0, 0, W, H); const d = x.getImageData(0, 0, W, H), rr = mb(4);
    for (let i = 0; i < W * H; i++) { const y = (i / W) | 0, xx = i % W, v = (rr() - 0.5) * 16 + Math.sin(y * 0.07 + Math.sin(xx * 0.013) * 3) * 3 - Math.hypot(xx - 600, y - 315) * 0.016; d.data[i * 4] += v; d.data[i * 4 + 1] += v; d.data[i * 4 + 2] += v * 1.2; }
    x.putImageData(d, 0, 0); return q; })();
  const knock = (seed, dens) => { const q = mk(), x = q.getContext('2d'), d = x.createImageData(W, H), rr = mb(seed);
    for (let i = 0; i < W * H; i++) d.data[i * 4 + 3] = rr() < dens ? 255 : 0; x.putImageData(d, 0, 0);
    x.strokeStyle = '#000'; for (let i = 0; i < 150; i++) { x.lineWidth = 0.6 + rr() * 1.2; x.globalAlpha = 0.5 + rr() * 0.5; const y = rr() * H, x0 = rr() * W, l = 40 + rr() * 260; x.beginPath(); x.moveTo(x0, y); x.quadraticCurveTo(x0 + l / 2, y + (rr() - 0.5) * 5, x0 + l, y + (rr() - 0.5) * 3); x.stroke(); }
    return q; };
  const knockK = knock(7, 0.035), knockR = knock(8, 0.09);

  // ---------- small drawing kit (g = a layer context; world coords under the camera transform)
  const poly = (g, pts, fill = 1) => { g.beginPath(); pts.forEach(([x, y], i) => (i ? g.lineTo(x, y) : g.moveTo(x, y))); g.closePath(); fill ? g.fill() : g.stroke(); };
  const cut = (g, fn) => { g.save(); g.globalCompositeOperation = 'destination-out'; fn(); g.restore(); };
  const line = (g, x0, y0, x1, y1, w) => { g.lineWidth = w; g.beginPath(); g.moveTo(x0, y0); g.lineTo(x1, y1); g.stroke(); };
  const GROUND = 468, GX = [380, 820], F = 1.3, CS = 1.2, CFY = 335, AW = 80, ATOP = 300;
  const arch = (g, cx, grow = 0) => { g.beginPath(); g.moveTo(cx - AW - grow, GROUND); g.lineTo(cx - AW - grow, ATOP); g.arc(cx, ATOP, AW + grow, Math.PI, 0); g.lineTo(cx + AW + grow, GROUND); g.closePath(); };
  function spearhead(g, x, y, s = 1, up = false) { // point at (x,y)
    const d = up ? 1 : -1; g.beginPath(); g.moveTo(x, y); g.quadraticCurveTo(x + 8.5 * s, y + d * 11 * s, x + 3 * s, y + d * 27 * s); g.lineTo(x - 3 * s, y + d * 27 * s); g.quadraticCurveTo(x - 8.5 * s, y + d * 11 * s, x, y); g.fill();
    cut(g, () => { g.strokeStyle = '#000'; line(g, x, y + d * 6 * s, x, y + d * 24 * s, 0.9 * s); line(g, x + 2.4 * s, y + d * 10 * s, x + 4.2 * s, y + d * 15 * s, 0.6 * s); line(g, x + 2 * s, y + d * 14 * s, x + 3.6 * s, y + d * 19 * s, 0.6 * s); });
  }
  function portcullis(cx, dy) {
    k.save(); arch(k, cx, -1); k.clip(); r.save(); arch(r, cx, -1); r.clip();
    k.fillStyle = BLK; r.fillStyle = RED;
    for (let i = 0; i < 7; i++) { const x = cx + (i - 3) * 22.6; k.fillRect(x - 2.7, GROUND + dy - 320, 5.4, 320 - 25); spearhead(k, x, GROUND + dy); }
    for (let j = 0; j < 6; j++) { const y = GROUND + dy - 38 - j * 44; r.fillRect(cx - AW, y, AW * 2, 6.5); for (let i = 0; i < 7; i++) { const x = cx + (i - 3) * 22.6; k.beginPath(); k.arc(x, y + 3.2, 3.6, 0, 7); k.fill(); } }
    k.restore(); r.restore();
  }
  function guard(x, flip, spearRot = 0) {
    k.save(); k.translate(x, GROUND); k.scale(flip * F, F); k.fillStyle = BLK; k.strokeStyle = BLK;
    poly(k, [[-11, 0], [-8, -36], [-1, -36], [-2, 0]]); poly(k, [[3, 0], [1, -36], [9, -36], [13, 0]]);
    poly(k, [[-16, -30], [-13, -72], [13, -72], [17, -30]]);
    cut(k, () => { k.strokeStyle = '#000'; for (let i = 0; i < 6; i++) line(k, -10 + i * 4.5, -34, -4 + i * 4.5, -66, 1.1); });
    k.beginPath(); k.arc(0, -82, 9.5, 0, 7); k.fill(); cut(k, () => { k.beginPath(); k.arc(1.5, -80, 5.6, -0.3, Math.PI * 0.9); k.fill(); }); k.fillRect(0.5, -84, 2, 8); // helmet with nose guard
    poly(k, [[-10, -90], [0, -98], [10, -90]]);
    k.save(); k.translate(19, -52); k.rotate(spearRot); k.fillRect(-1.8, -84, 3.6, 136); spearhead(k, 0, -112, 1.15, true); k.restore();
    k.beginPath(); k.arc(18, -52, 4.6, 0, 7); k.fill();
    k.beginPath(); k.arc(-13, -50, 15.5, 0, 7); k.fill(); cut(k, () => { k.beginPath(); k.arc(-13, -50, 11.5, 0, 7); k.fill(); }); line(k, -13, -61, -13, -39, 1.6); line(k, -24, -50, -2, -50, 1.6);
    k.restore();
    r.save(); r.translate(x, GROUND); r.scale(flip * F, F); r.fillStyle = RED; r.beginPath(); r.arc(-13, -50, 4.6, 0, 7); r.fill(); r.fillRect(-13, -100, 26, 4); r.restore();
  }
  function coin(g, x, y, rad, rot) {
    r.fillStyle = RED; r.beginPath(); r.arc(x, y, rad, 0, 7); r.fill();
    k.strokeStyle = BLK; k.lineWidth = rad * 0.16; k.beginPath(); k.arc(x, y, rad, 0, 7); k.stroke();
    k.save(); k.translate(x, y); k.rotate(rot); k.fillStyle = BLK; spearhead(k, 0, -rad * 0.62, rad / 24, true); k.fillRect(-rad * 0.06, -rad * 0.1, rad * 0.12, rad * 0.7); k.restore();
  }
  function thief(x, caught) {
    k.save(); k.translate(x, GROUND); k.rotate(0.1); k.scale(F, F); k.fillStyle = BLK;
    cut(k, () => { k.fillStyle = '#000'; poly(k, [[-21, 0], [-16, -73], [0, -107], [16, -75], [27, 0]]); k.beginPath(); k.arc(-25, -52, 21, 0, 7); k.fill(); });
    poly(k, [[-15, 0], [-11, -70], [0, -99], [11, -72], [20, 0]]);
    cut(k, () => { k.strokeStyle = '#000'; k.fillStyle = '#000'; poly(k, [[2, -84], [9, -78], [3, -73]]); for (let i = 0; i < 5; i++) line(k, -8 + i * 5, -8, -5 + i * 4, -58, 1); });
    k.fillRect(-13, -4, 12, 4); k.fillRect(6, -4, 14, 4);
    k.beginPath(); k.arc(-25, -52, 17, 0, 7); k.fill(); cut(k, () => { k.beginPath(); k.arc(-25, -52, 13.6, 0, 7); k.fill(); });
    k.strokeStyle = BLK; line(k, -14, -64, 4, -62, 3); if (!caught) { for (let i = 0; i < 4; i++) line(k, -34 + i * 5, -44, -30 + i * 5, -58, 1); }
    k.restore();
  }

  // static wall detail, generated once in world coords
  const rr0 = mb(31), BR = []; for (let y = 140; y < GROUND; y += 30) { const off = ((y / 30) | 0) % 2 ? 23 : 0; for (let x = 60 + off; x < 1150; x += 46) BR.push([x + (rr0() - 0.5) * 4, y, 22 + rr0() * 8]); }
  const SKY = []; for (let i = 0; i < 26; i++) SKY.push([60 + rr0() * 1000, 62 + ((rr0() * 6) | 0) * 9, 40 + rr0() * 150]);
  const wallTop = (x) => (Math.abs(x - GX[0]) < 132 || Math.abs(x - GX[1]) < 132 ? 122 : 176);
  function wall() {
    const pts = [[44, GROUND]]; let x = 44; while (x < 1156) { const top = wallTop(x + 1), nx = Math.min(1156, x + 22), up = (((x - 44) / 22) | 0) % 2 === 0; const chg = wallTop(nx + 1) !== top; pts.push([x, top + (up ? 0 : 18)], [nx, top + (up ? 0 : 18)]); x = nx; }
    pts.push([1156, GROUND]);
    k.save(); k.beginPath(); pts.forEach(([px, py], i) => (i ? k.lineTo(px, py) : k.moveTo(px, py))); k.closePath(); k.strokeStyle = BLK; k.lineWidth = 4.2; k.lineJoin = 'miter'; k.stroke(); k.clip();
    k.lineCap = 'butt'; for (let y = 140; y < GROUND; y += 30) line(k, 44, y + 0.8 * Math.sin(y), 1156, y - 0.8 * Math.sin(y * 2), 1.5);
    BR.forEach(([bx, by, h]) => line(k, bx, by, bx + 0.6, by + 30, 1.3));
    [GX[0] + 132, GX[1] + 132].forEach((tx) => { k.save(); k.beginPath(); k.rect(tx - 40, 100, 40, 400); k.clip(); for (let i = -40; i < 440; i += 6.5) line(k, tx - 44, 100 + i + 40, tx + 4, 100 + i, 1.7); k.restore(); line(k, tx, 122, tx, GROUND, 3.4); line(k, tx - 264, 122, tx - 264, GROUND, 3.4); });
    k.restore();
    GX.forEach((cx) => { // archway: cleared, hatched dark, ring of voussoirs
      cut(k, () => { arch(k, cx, 12); k.fill(); }); k.save(); arch(k, cx, 12); k.strokeStyle = BLK; k.lineWidth = 4; k.stroke();
      for (let a = 0; a <= 12; a++) { const an = Math.PI + (a / 12) * Math.PI; line(k, cx + Math.cos(an) * AW, ATOP + Math.sin(an) * AW, cx + Math.cos(an) * (AW + 12), ATOP + Math.sin(an) * (AW + 12), 1.6); }
      arch(k, cx, 0); k.lineWidth = 2.6; k.stroke(); k.clip();
      for (let y = 222; y < GROUND; y += 5) line(k, cx - AW, y, cx + AW, y, y < 300 ? 2.4 : y < 380 ? 1.7 : 1.25);
      k.restore();
    });
    k.fillStyle = BLK; k.fillRect(30, GROUND, 1140, 4.5); const g2 = mb(5); for (let i = 0; i < 70; i++) { const gx = 50 + g2() * 1100; line(k, gx, GROUND + 8 + g2() * 9, gx + 14 + g2() * 30, GROUND + 8 + g2() * 9, 1.5); }
    SKY.forEach(([sx, sy, l]) => line(k, sx, sy, sx + l, sy, 1.5));
  }
  const LATE = [];
  const small = (...a) => LATE.push(a);
  const text = (g, s, x, y, font, col, align = 'center') => { g.font = font; g.fillStyle = col; g.textAlign = align; g.textBaseline = 'alphabetic'; g.fillText(s, x, y); };
  function plaque(cx, s) { k.fillStyle = BLK; k.fillRect(cx - 44, 150, 88, 44); cut(k, () => { k.fillStyle = '#000'; k.fillRect(cx - 40, 154, 80, 36); }); text(k, s, cx, 184, '400 34px Gloock', BLK); }

  function border() {
    [k, r].forEach((g) => { g.setTransform(1, 0, 0, 1, 0, 0); });
    cut(k, () => { k.fillStyle = '#000'; k.fillRect(0, 0, W, 44); k.fillRect(0, H - 44, W, 44); k.fillRect(0, 0, 44, H); k.fillRect(W - 44, 0, 44, H); });
    cut(r, () => { r.fillStyle = '#000'; r.fillRect(0, 0, W, 44); r.fillRect(0, H - 44, W, 44); r.fillRect(0, 0, 44, H); r.fillRect(W - 44, 0, 44, H); });
    k.strokeStyle = BLK; k.lineWidth = 3.5; k.strokeRect(14, 14, W - 28, H - 28); k.lineWidth = 2; k.strokeRect(42, 42, W - 84, H - 84);
    k.fillStyle = BLK; r.fillStyle = RED;
    for (let x = 52, i = 0; x < W - 50; x += 20, i++) { const g = i % 4 === 2 ? r : k; poly(g, [[x, 20], [x + 14, 20], [x + 7, 37]]); poly(g, [[x, H - 20], [x + 14, H - 20], [x + 7, H - 37]]); }
    for (let y = 52, i = 0; y < H - 50; y += 20, i++) { const g = i % 4 === 2 ? r : k; poly(g, [[20, y], [20, y + 14], [37, y + 7]]); poly(g, [[W - 20, y], [W - 20, y + 14], [W - 37, y + 7]]); }
    [[28, 28], [W - 28, 28], [28, H - 28], [W - 28, H - 28]].forEach(([x, y]) => { r.fillRect(x - 11, y - 11, 22, 22); poly(k, [[x, y - 8], [x + 8, y], [x, y + 8], [x - 8, y]]); });
  }

  const SLAM = 0.42, WIDE0 = 0.8, WIDE1 = 1.5;
  onSeek.push((t) => {
    LATE.length = 0; [k, r].forEach((g) => { g.setTransform(1, 0, 0, 1, 0, 0); g.globalCompositeOperation = 'source-over'; g.globalAlpha = 1; g.clearRect(0, 0, W, H); });
    const endCard = t >= 5.8;
    if (!endCard) {
      // camera
      let u = cl((t - WIDE0) / (WIDE1 - WIDE0)); u = u < 0.5 ? 16 * u ** 5 : 1 - ((-2 * u + 2) ** 5) / 2;
      const s = Math.exp(Math.log(7.3) * (1 - u) + Math.log(CS) * u), fx = GX[0] + (600 - GX[0]) * u, fy = 430.9 + (CFY - 430.9) * u;
      const sk = (t0, amp) => { const q = Math.floor((t - t0) * 30 + 1e-6); return q < 0 || q > 5 ? 0 : [1, -0.7, 0.45, -0.25, 0.12, 0][q] * amp; };
      const shY = sk(SLAM, 20) + sk(3.92, 7), shX = sk(SLAM, -6);
      [k, r].forEach((g) => g.setTransform(s, 0, 0, s, 600 - fx * s + shX, 315 - fy * s + shY));
      wall();
      // portcullises: both fall at the start; IN ratchets up for the coin, OUT stays up until the catch
      const fall = t < SLAM ? -31 * (1 - (t / SLAM) ** 2) : 0;
      const ratchet = (t0) => { const q = Math.floor((t - t0) * 10 + 1e-6); return q < 0 ? 0 : [-34, -30, -78, -74, -128, -124, -150][Math.min(q, 6)]; };
      const dyIn = t < 1.62 ? fall : ratchet(1.62), dyOut = t < 1.62 ? fall : t < 3.92 ? ratchet(1.72) : Math.min(0, -150 + ((t - 3.92) / 0.1) * 150);
      portcullis(GX[0], dyIn); portcullis(GX[1], dyOut);
      // the thief steps out of the OUT arch; the portcullis drops behind him
      if (t >= 3.15) { const q = Math.min(4, Math.floor((t - 3.15) * 8 + 1e-6)), tx = GX[1] + [-2, 12, 28, 42, 52][q]; const caught = t >= 3.92; if (caught) { // rays first, behind
          r.save(); r.translate(tx - 25.6, GROUND - 70.5); r.scale(F, F); r.fillStyle = RED; const fl = Math.floor(t * 10) % 2; for (let i = 0; i < 14; i++) { r.rotate((Math.PI * 2) / 14); poly(r, [[-2.4, -24], [0, -44 - (i % 2 ? 10 : 0) - fl * 3], [2.4, -24]]); } r.restore(); }
        thief(tx, caught); if (caught) coin(k, tx - 25.6, GROUND - 70.5, 15, 0.5); }
      guard(GX[0] - 128, 1); guard(GX[1] + 128, -1, t >= 3.92 ? -1.02 : 0);
      if (t >= 1.5) { plaque(GX[0], 'IN'); plaque(GX[1], 'OUT'); }
      // marked coin rolls in at the IN gate
      if (t >= 1.9 && t < 2.82) { const q = Math.floor((t - 1.9) * 15 + 1e-6) / 15, cx = 118 + (q / 0.86) * (GX[0] - 118); k.save(); r.save(); [k, r].forEach((g) => { g.beginPath(); g.rect(0, 0, GX[0] - 2, 630); g.clip(); }); coin(k, cx, GROUND - 23, 22, cx / 22); k.restore(); r.restore(); }
      if (t >= SLAM && t < SLAM + 0.2) { r.fillStyle = RED; for (let i = 0; i < 7; i++) { const x = GX[0] + (i - 3) * 22.6; poly(r, [[x - 7, GROUND - 1], [x - 10, GROUND - 6], [x - 4.5, GROUND - 3]]); poly(r, [[x + 7, GROUND - 1], [x + 10.5, GROUND - 7], [x + 4.5, GROUND - 3]]); } }
      // the two real calls, set under their gates (screen space, so the type stays one size)
      [k, r].forEach((g) => g.setTransform(1, 0, 0, 1, 0, 0)); const X = (x) => 600 + (x - 600) * CS;
      if (t < 4.6) {
        if (t >= 1.72) small(k, 'spear.pre(messages)', X(GX[0]), 524, '600 25px "Plex Mono"', BLK);
        if (t >= 2.82) small(k, 'allowed: true', X(GX[0]), 556, '500 22px "Plex Mono"', BLK);
        if (t >= 3.4) small(k, 'spear.post({ output, canary })', X(GX[1]), 524, '600 25px "Plex Mono"', BLK);
        if (t >= 3.92) small(r, 'allowed: false', X(GX[1]), 556, '600 22px "Plex Mono"', RED);
      } else { small(k, 'Canary tokens make exfiltration visible', 600, 544, '400 40px Gloock', BLK); r.fillStyle = RED; r.fillRect(246, 558, 708, 4); }
    } else {
      // colophon
      const q = Math.floor((t - 5.8) * 12 + 1e-6);
      k.save(); k.translate(176, 0); k.fillStyle = BLK; k.fillRect(-7, 150, 14, 420); spearhead(k, 0, 62, 5.2, true); k.fillRect(-22, 196, 44, 9); k.restore();
      r.fillStyle = RED; r.beginPath(); r.arc(176, 408, 58, 0, 7); r.fill();
      k.strokeStyle = BLK; k.lineWidth = 7; k.beginPath(); k.arc(176, 408, 58, 0, 7); k.stroke(); k.fillRect(169, 150, 14, 420);
      for (let i = 0; i < 9; i++) line(k, 196 + i * 3.6, 372 + i * 5, 222 - i * 0.5, 388 + i * 6.5, 1.6);
      text(k, 'Spear', 286, 262, '400 196px Gloock', BLK, 'left');
      r.fillStyle = RED; r.fillRect(292, 290, 812, 5);
      if (q >= 2) { small(k, 'Defense-in-depth security middleware', 292, 346, '400 39px Gloock', BLK, 'left'); small(k, 'for LLM I/O pipelines.', 292, 392, '400 39px Gloock', BLK, 'left'); }
      if (q >= 4) { r.fillStyle = RED; r.fillRect(292, 430, 520, 54); cut(r, () => { r.font = '600 27px "Plex Mono"'; r.textAlign = 'left'; r.fillStyle = '#000'; r.fillText('npm install @spear-secure/core', 310, 466); }); }
      if (q >= 6) { small(k, 'Open source · AGPL-3.0-only', 292, 540, '500 21px "Plex Mono"', BLK, 'left'); small(k, 'Built by Sunny Patneedi', 1104, 540, '500 21px "Plex Mono"', BLK, 'right'); }
    }
    border();
    // uneven inking, then print: red first, black on top, both multiplied onto vellum; red sits slightly out of register
    [[k, knockK], [r, knockR]].forEach(([g, kn]) => { g.setTransform(1, 0, 0, 1, 0, 0); g.globalCompositeOperation = 'destination-out'; g.drawImage(kn, 0, 0); g.globalCompositeOperation = 'source-over'; });
    LATE.splice(0).forEach((a) => text(...a)); // small type goes on after the wear, so it stays readable
    k.globalCompositeOperation = 'destination-out'; k.globalAlpha = 0.35; k.drawImage(knockR, 0, 0); k.globalAlpha = 1; k.globalCompositeOperation = 'source-over';
    c.globalCompositeOperation = 'source-over'; c.drawImage(vellum, 0, 0);
    c.globalCompositeOperation = 'multiply'; c.drawImage(RC, 3, -2.5); c.drawImage(KC, 0, 0);
  });
  end();
})();
