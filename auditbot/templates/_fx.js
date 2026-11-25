/* Shared visual effects for the interactive tabs: confetti, flying numbers, toasts, shake, flash. */
window.FX = (function () {
  "use strict";
  var RM = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var cv = document.getElementById("fx"), ctx = cv.getContext && cv.getContext("2d");
  var P = [], running = false, dpr = Math.min(2, window.devicePixelRatio || 1);
  var COLS = ["#22d3ee", "#a78bfa", "#f472b6", "#34d399", "#fbbf24", "#ffffff"];
  function size() { cv.width = innerWidth * dpr; cv.height = innerHeight * dpr; }
  size(); addEventListener("resize", size);

  function confetti(x, y, n, power) {
    if (RM || !ctx) return;
    n = n || 150; power = power || 1;
    for (var i = 0; i < n; i++) {
      var a = Math.random() * Math.PI * 2, v = (3 + Math.random() * 10) * power;
      P.push({ x: x, y: y, vx: Math.cos(a) * v, vy: Math.sin(a) * v - 7 * power, r: 3 + Math.random() * 4, c: COLS[i % COLS.length],
        rot: Math.random() * 6, vr: (Math.random() - 0.5) * 0.4, life: 1, shape: i % 3 });
    }
    if (!running) { running = true; requestAnimationFrame(tick); }
  }
  function tick() {
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, innerWidth, innerHeight);
    P = P.filter(function (p) { return p.life > 0 && p.y < innerHeight + 40; });
    P.forEach(function (p) {
      p.vy += 0.25; p.vx *= 0.985; p.x += p.vx; p.y += p.vy; p.rot += p.vr; p.life -= 0.0055;
      ctx.save(); ctx.globalAlpha = Math.max(0, Math.min(1, p.life * 1.6)); ctx.translate(p.x, p.y); ctx.rotate(p.rot); ctx.fillStyle = p.c;
      if (p.shape === 0) ctx.fillRect(-p.r, -p.r / 2, p.r * 2, p.r);
      else if (p.shape === 1) { ctx.beginPath(); ctx.arc(0, 0, p.r / 1.4, 0, 6.283); ctx.fill(); }
      else { ctx.beginPath(); ctx.moveTo(0, -p.r); ctx.lineTo(p.r, p.r); ctx.lineTo(-p.r, p.r); ctx.fill(); }
      ctx.restore();
    });
    if (P.length) requestAnimationFrame(tick); else { running = false; ctx.clearRect(0, 0, innerWidth, innerHeight); }
  }
  function centerOf(el) { var r = el.getBoundingClientRect(); return { x: r.left + r.width / 2, y: r.top + r.height / 2 }; }

  function float(text, from, to, color) {
    var e = document.createElement("div");
    e.className = "floatnum"; e.textContent = text; e.style.color = color; e.style.left = from.x + "px"; e.style.top = from.y + "px";
    document.body.appendChild(e);
    if (RM || !e.animate) { setTimeout(function () { e.remove(); }, 500); return; }
    var dx = to ? to.x - from.x : 0, dy = to ? to.y - from.y : -80;
    e.animate([
      { transform: "translate(-50%,-50%) scale(.5)", opacity: 0 },
      { transform: "translate(-50%,-50%) scale(1.5)", opacity: 1, offset: 0.2 },
      { transform: "translate(calc(-50% + " + dx + "px),calc(-50% + " + dy + "px)) scale(.7)", opacity: 0.1 }
    ], { duration: 950, easing: "cubic-bezier(.5,0,.3,1)" }).onfinish = function () { e.remove(); };
  }
  function toast(title, body, kind) {
    var host = document.getElementById("toasts"), t = document.createElement("div");
    t.className = "toast " + (kind || ""); t.innerHTML = "<b></b><span></span>";
    t.firstChild.textContent = title; t.lastChild.textContent = body; host.appendChild(t);
    while (host.children.length > 3) host.firstChild.remove();
    setTimeout(function () { t.classList.add("out"); setTimeout(function () { t.remove(); }, 450); }, 3400);
  }
  function shake(el) {
    if (RM || !el || !el.animate) return;
    el.animate([{ transform: "translate(0,0)" }, { transform: "translate(-9px,2px)" }, { transform: "translate(8px,-3px)" },
      { transform: "translate(-6px,1px)" }, { transform: "translate(3px,0)" }, { transform: "translate(0,0)" }], { duration: 430 });
  }
  function flash(color) {
    var f = document.getElementById("flash"); if (RM || !f.animate) return;
    f.style.background = "radial-gradient(ellipse at center,transparent 30%," + color + ")";
    f.animate([{ opacity: 0 }, { opacity: 1 }, { opacity: 0 }], { duration: 550 });
  }
  return { RM: RM, confetti: confetti, float: float, toast: toast, shake: shake, flash: flash, centerOf: centerOf };
})();
