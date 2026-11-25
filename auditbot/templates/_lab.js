/* Readiness Lab: a playable what-if simulator over this scan's control tests.
   Scoring mirrors scanner.ScanResult.score: severity-weighted share of applicable tests passing, Python-style rounding. */
(function () {
  "use strict";
  var EV = JSON.parse(document.getElementById("ev").textContent);
  var W = { critical: 10, high: 5, medium: 2, low: 1 };
  var C = 2 * Math.PI * 106, C2 = 2 * Math.PI * 126, READY = 85;
  var $ = function (s) { return document.querySelector(s); };
  var esc = function (s) { return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); };
  var pyRound = function (x) { var f = Math.floor(x); return Math.abs(x - f - 0.5) < 1e-9 ? (f % 2 ? f + 1 : f) : Math.round(x); };
  var wOf = function (t) { return W[t.severity] || 1; };

  var tests = EV.control_tests.filter(function (t) { return t.status !== "N/A"; });
  var byId = {}; tests.forEach(function (t) { byId[t.id] = t; });
  var orig = {}; tests.forEach(function (t) { orig[t.id] = t.status === "PASS"; });
  var st = Object.assign({}, orig);
  var total = tests.reduce(function (a, t) { return a + wOf(t); }, 0);
  var earned = function () { return tests.reduce(function (a, t) { return a + (st[t.id] ? wOf(t) : 0); }, 0); };
  var score = function () { return total ? pyRound(100 * earned() / total) : 100; };
  var colors = function (s) { return s >= READY ? ["#22d3ee", "#34d399"] : s >= 60 ? ["#fb923c", "#fbbf24"] : ["#e11d48", "#f43f5e"]; };
  var rankOf = function (s) { return s >= 100 ? "S" : s >= READY ? "A" : s >= 70 ? "B" : s >= 55 ? "C" : s >= 40 ? "D" : "F"; };

  var lg = $("#lg"), svg = $("#labSvg"), arc = $("#labArc"), ghost = $("#labGhost"), knob = $("#labKnob"), stage = $("#labStage");
  var numEl = $("#labNum"), rankEl = $("#labRank"), ptsEl = $("#labPts"), tgtEl = $("#labTarget"), planEl = $("#labPlan");
  var deck = $("#deck"), autoBtn = $("#labAuto"), achEl = $("#ach");
  var target = score() >= READY ? 100 : READY, breaks = 0, busy = false, introDone = false, lastRank = "";

  /* ---------- achievements ---------- */
  var ACH = [
    { id: "first", i: "🔧", n: "First fix", d: "Remediate any control" },
    { id: "crit", i: "🎯", n: "Critical thinker", d: "Fix a critical-severity control" },
    { id: "ready", i: "🛡️", n: "Audit ready", d: "Reach " + READY + "% readiness" },
    { id: "flawless", i: "💎", n: "Flawless", d: "Hit 100%" },
    { id: "auto", i: "⚡", n: "Autopilot", d: "Reach a target with auto-fix" },
    { id: "chaos", i: "🔥", n: "Chaos engineer", d: "Break 3 controls" },
    { id: "melt", i: "☢️", n: "Meltdown", d: "Drop below 25%" }
  ];
  var got = {};
  achEl.innerHTML = ACH.map(function (a) { return '<div class="badge" data-a="' + a.id + '"><span class="bi">' + a.i + "</span><div><b>" + a.n + "</b><small>" + a.d + "</small></div></div>"; }).join("");
  $("#achT").textContent = ACH.length;
  function unlock(id) {
    if (got[id]) return; got[id] = true;
    var a = ACH.filter(function (x) { return x.id === id; })[0], b = achEl.querySelector('[data-a="' + id + '"]');
    b.classList.add("on", "new"); setTimeout(function () { b.classList.remove("new"); }, 700);
    $("#achN").textContent = Object.keys(got).length;
    FX.toast("🏆 Achievement unlocked · " + a.n, a.d, "");
  }

  /* ---------- control deck ---------- */
  var order = tests.slice().sort(function (a, b) { return (orig[a.id] - orig[b.id]) || (wOf(b) - wOf(a)); });
  deck.innerHTML = order.map(function (t) {
    return '<button class="ctl" data-id="' + esc(t.id) + '"><div class="row"><span class="cst"></span><span class="cw"></span></div>' +
      "<b>" + esc(t.title) + "</b><small>" + esc(t.severity.toUpperCase() + " · " + t.soc2.concat(t.iso27001).join(" · ")) + '</small><span class="act"></span></button>';
  }).join("");
  function renderDeck(need) {
    var needIds = {}; (need || []).forEach(function (t) { needIds[t.id] = 1; });
    Array.prototype.forEach.call(deck.children, function (b) {
      var t = byId[b.dataset.id], ok = st[t.id], w = wOf(t);
      b.classList.toggle("pass", ok); b.classList.toggle("fail", !ok); b.classList.toggle("need", !!needIds[t.id]);
      b.querySelector(".cst").textContent = ok ? "PASS" : "FAIL";
      b.querySelector(".cw").textContent = ok ? w + " pts" : "+" + w;
      b.querySelector(".act").textContent = ok ? "CLICK TO BREAK" : "CLICK TO FIX ▸";
      b.setAttribute("aria-label", t.title + ": " + (ok ? "passing, click to break" : "failing, click to fix") + " (" + w + " points)");
    });
  }

  /* ---------- odometer number ---------- */
  function odo(v) {
    if (!numEl.firstChild) {
      var strip = "0123456789".split("").map(function (d) { return "<span>" + d + "</span>"; }).join("");
      numEl.innerHTML = [0, 1, 2].map(function () { return '<span class="dg"><span class="strip">' + strip + "</span></span>"; }).join("") + "<small>%</small>";
    }
    var s = ("00" + v).slice(-3);
    Array.prototype.forEach.call(numEl.querySelectorAll(".dg"), function (d, i) {
      d.classList.toggle("off", (i === 0 && v < 100) || (i === 1 && v < 10));
      d.firstChild.style.transform = "translateY(" + -Number(s[i]) + "em)";
    });
    numEl.setAttribute("aria-label", v + " percent");
  }

  /* ---------- gauge + plan ---------- */
  function needed() {
    var fails = tests.filter(function (t) { return !st[t.id]; }).sort(function (a, b) { return wOf(b) - wOf(a); });
    var out = [], e = earned();
    for (var i = 0; i < fails.length && pyRound(100 * e / total) < target; i++) { out.push(fails[i]); e += wOf(fails[i]); }
    return { list: out, proj: pyRound(100 * e / total) };
  }
  function renderPlan() {
    var n = needed(), s = score();
    if (!n.list.length) planEl.innerHTML = s >= target ? "✓ Target met: you're at <b>" + s + "%</b>." + (s < 100 ? " Drag the dial higher." : " Perfect score.") : "";
    else planEl.innerHTML = "Fix <b>" + n.list.length + "</b> control" + (n.list.length > 1 ? "s" : "") + " to reach <b>" + n.proj + "%</b>, highest-value first:<br>" +
      n.list.map(function (t) { return '<span class="chip"><b>+' + wOf(t) + "</b> " + esc(t.id) + "</span>"; }).join("");
    autoBtn.disabled = !n.list.length || busy;
    autoBtn.textContent = n.list.length ? "⚡ Auto-fix " + n.list.length + " to target" : "⚡ Auto-fix to target";
    renderDeck(n.list);
  }
  function renderGauge() {
    var s = score(), c = colors(s), r = rankOf(s);
    arc.style.strokeDashoffset = C * (1 - s / 100);
    $("#labS1").setAttribute("stop-color", c[0]); $("#labS2").setAttribute("stop-color", c[1]);
    lg.style.setProperty("--c", c[1]); stage.style.setProperty("--c", c[1]);
    odo(s);
    if (r !== lastRank) { rankEl.textContent = r; rankEl.classList.remove("pop"); void rankEl.offsetWidth; rankEl.classList.add("pop"); lastRank = r; }
    ptsEl.textContent = earned() + " / " + total + " PTS";
  }
  function setTarget(v) {
    target = Math.max(1, Math.min(100, Math.round(v)));
    var a = target / 100 * 2 * Math.PI;
    knob.setAttribute("transform", "translate(" + (150 + 126 * Math.sin(a)).toFixed(1) + " " + (150 - 126 * Math.cos(a)).toFixed(1) + ")");
    ghost.setAttribute("stroke-dasharray", (C2 * target / 100).toFixed(1) + " " + C2.toFixed(1));
    tgtEl.textContent = target + "%"; knob.setAttribute("aria-valuenow", target);
    renderPlan();
  }

  /* ---------- milestones ---------- */
  function milestone(before, after) {
    var g = FX.centerOf(lg);
    if (after >= READY && before < READY) { FX.confetti(g.x, g.y, 170); FX.toast("✅ AUDIT READY · " + after + "%", "Crossed the " + READY + "% audit-ready line.", "good"); unlock("ready"); }
    if (after === 100 && before < 100) { FX.confetti(g.x, g.y, 260, 1.3); setTimeout(function () { FX.confetti(innerWidth * 0.2, innerHeight * 0.4, 120); FX.confetti(innerWidth * 0.8, innerHeight * 0.4, 120); }, 250); unlock("flawless"); }
    if (before >= READY && after < READY) FX.toast("⚠ Readiness lost · " + after + "%", "Below the " + READY + "% audit-ready line.", "bad");
    if (after < 25) unlock("melt");
  }

  /* ---------- interactions ---------- */
  function toggle(id, b) {
    var t = byId[id], w = wOf(t), before = score();
    st[id] = !st[id];
    var from = FX.centerOf(b), to = FX.centerOf(lg);
    b.classList.remove("flip"); void b.offsetWidth; b.classList.add("flip");
    if (st[id]) {
      FX.float("+" + w, from, to, "#34d399");
      unlock("first"); if (t.severity === "critical") unlock("crit");
    } else {
      breaks++;
      FX.float("−" + w, from, null, "#f43f5e"); FX.shake(stage); FX.flash("rgba(244,63,94,.55)");
      numEl.classList.remove("glitch"); void numEl.offsetWidth; numEl.classList.add("glitch");
      if (breaks >= 3) unlock("chaos");
    }
    renderPlan();
    var after = score();
    setTimeout(function () { renderGauge(); milestone(before, after); }, st[id] && !FX.RM ? 520 : 0);
  }
  deck.addEventListener("click", function (e) { var b = e.target.closest(".ctl"); if (b && !busy) toggle(b.dataset.id, b); });

  autoBtn.addEventListener("click", function () {
    var list = needed().list; if (!list.length || busy) return;
    busy = true; autoBtn.disabled = true; var i = 0;
    (function next() {
      if (i >= list.length) { busy = false; renderPlan(); if (score() >= target) setTimeout(function () { unlock("auto"); }, 600); return; }
      var t = list[i++], b = deck.querySelector('[data-id="' + t.id + '"]');
      toggle(t.id, b); setTimeout(next, FX.RM ? 0 : 700);
    })();
  });
  $("#labReset").addEventListener("click", function () {
    if (busy) return;
    st = Object.assign({}, orig); breaks = 0; renderPlan(); renderGauge();
    FX.toast("↺ Back to the scanned state", "Readiness " + score() + "% · achievements kept", "");
  });

  /* dial: drag anywhere on the ring to move the target knob */
  var dragging = false;
  function fromEvent(e, jump) {
    var p = svg.createSVGPoint(); p.x = e.clientX; p.y = e.clientY;
    var q = p.matrixTransform(svg.getScreenCTM().inverse());
    var a = Math.atan2(q.x - 150, -(q.y - 150)); if (a < 0) a += 2 * Math.PI;
    var v = a / (2 * Math.PI) * 100;
    if (!jump) { if (target > 75 && v < 25) v = 100; else if (target < 25 && v > 75) v = 1; }
    setTarget(v);
  }
  svg.addEventListener("pointerdown", function (e) { dragging = true; lg.classList.add("drag"); try { svg.setPointerCapture(e.pointerId); } catch (x) {} fromEvent(e, true); e.preventDefault(); });
  svg.addEventListener("pointermove", function (e) { if (dragging) fromEvent(e, false); });
  ["pointerup", "pointercancel"].forEach(function (ev) { svg.addEventListener(ev, function () { dragging = false; lg.classList.remove("drag"); }); });
  knob.addEventListener("keydown", function (e) {
    var d = { ArrowRight: 1, ArrowUp: 1, ArrowLeft: -1, ArrowDown: -1, PageUp: 5, PageDown: -5 }[e.key];
    if (e.key === "Home") d = 1 - target; if (e.key === "End") d = 100 - target;
    if (d) { setTarget(target + d); e.preventDefault(); }
  });

  /* ---------- init ---------- */
  odo(0); setTarget(target); renderDeck(needed().list);
  document.addEventListener("tabshow", function (e) {
    if (e.detail !== "lab" || introDone) return;
    introDone = true;
    setTimeout(renderGauge, FX.RM ? 0 : 450);
  });
})();
