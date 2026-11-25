/* Auditus signature moments: wordmark decode on boot, the auditor's stamp, and Proof Mode
   (hover any number on the Report tab to see exactly how it was derived and which evidence it points to). */
(function () {
  "use strict";
  var EV = JSON.parse(document.getElementById("ev").textContent);
  var W = { critical: 10, high: 5, medium: 2, low: 1 };
  var RM = FX.RM;
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  var esc = function (s) { return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); };
  var bootDone = function () { var b = $("#boot"); return !b || b.classList.contains("done"); };

  /* ---------- wordmark decode on the boot screen ---------- */
  (function () {
    var el = $("#bootWord"); if (!el || RM || bootDone()) return;
    var word = "AUDITUS", glyphs = "ABCDEFGHIJKLMNOPQRSTUVWXYZ#%&*$§01", t0 = performance.now(), dur = 1100;
    (function f(t) {
      var k = Math.min(1, (t - t0) / dur), fixed = Math.floor(word.length * k), s = word.slice(0, fixed);
      for (var i = fixed; i < word.length; i++) s += glyphs[(Math.random() * glyphs.length) | 0];
      el.textContent = s; if (k < 1) requestAnimationFrame(f); else el.textContent = word;
    })(t0);
  })();

  /* ---------- the auditor's stamp ---------- */
  var stamp = $("#stamp"), stamped = false;
  function slam() {
    if (!stamp) return;
    if (RM) { stamp.classList.add("shown"); return; }
    stamp.classList.remove("slam"); void stamp.offsetWidth; stamp.classList.add("slam");
    setTimeout(function () {
      var r = stamp.getBoundingClientRect(), c = { x: r.left + r.width / 2, y: r.top + r.height / 2 };
      var ring = document.createElement("div"); ring.className = "inkring";
      ring.style.cssText = "left:" + c.x + "px;top:" + c.y + "px;width:" + r.width + "px;height:" + r.height + "px;--w2:" + (r.width * 1.5) + "px;--h2:" + (r.height * 1.9) + "px;--sc:" + getComputedStyle(stamp).getPropertyValue("--sc");
      document.body.appendChild(ring); setTimeout(function () { ring.remove(); }, 800);
      FX.shake($("header.hero"));
      if (stamp.classList.contains("ok")) { FX.confetti(c.x, c.y, 160, 1); FX.toast("✅ Audit ready", "Verified by Auditus at " + EV.summary.readiness_score + "%.", "good"); }
      else FX.flash(stamp.classList.contains("bad") ? "rgba(244,63,94,.45)" : "rgba(251,191,36,.35)");
    }, 300);
  }
  function stampWhenVisible() {
    if (stamped || !$("#p-report").classList.contains("on")) return;
    stamped = true;
    (function wait() { if (!bootDone()) return setTimeout(wait, 150); setTimeout(slam, RM ? 0 : 2500); })();
  }
  if (stamp) stamp.addEventListener("click", slam);
  document.addEventListener("tabshow", function (e) { if (e.detail === "report") stampWhenVisible(); });

  /* ---------- proof mode ---------- */
  var tests = EV.control_tests, app = tests.filter(function (t) { return t.status !== "N/A"; });
  var pts = function (a) { return a.reduce(function (s, t) { return s + (W[t.severity] || 1); }, 0); };
  var pass = app.filter(function (t) { return t.status === "PASS"; }), fail = app.filter(function (t) { return t.status === "FAIL"; });
  var na = tests.length - app.length, S = EV.summary.readiness_score;
  var row = function (a, b, c, cls) { return [a, b, c, cls || ""]; };
  var sevRows = function (list) {
    return ["critical", "high", "medium", "low"].map(function (s) {
      var a = list.filter(function (t) { return t.severity === s; }); if (!a.length) return null;
      var p = a.filter(function (t) { return t.status === "PASS"; });
      return row(s.toUpperCase() + " ×" + W[s], p.length + "/" + a.length + " tests pass", pts(p) + "/" + pts(a) + " pts", p.length === a.length ? "g" : "r");
    }).filter(Boolean);
  };
  var PROOFS = {
    score: function () {
      var exact = pts(app) ? (100 * pts(pass) / pts(app)).toFixed(2) : "100.00";
      return { t: "Readiness score", f: "Σ passing weights / Σ applicable weights<br>= " + pts(pass) + " / " + pts(app) + " = " + exact + "% → <em>" + S + "%</em>",
        rows: sevRows(app), note: (na ? na + " N/A test" + (na > 1 ? "s" : "") + " excluded · " : "") + "weights: critical 10 · high 5 · medium 2 · low 1", rel: ".test.FAIL", relName: "failing tests" };
    },
    pass: function () { return { t: "Control tests passing", f: pass.length + " PASS of " + app.length + " applicable", rows: pass.map(function (t) { return row("✓", t.id, t.severity, "g"); }), rel: ".test.PASS", relName: "passing tests" }; },
    fail: function () { return { t: "Control tests failing", f: fail.length + " FAIL · costing " + pts(fail) + " of " + pts(app) + " pts", rows: fail.map(function (t) { return row("✕", t.id, "−" + (W[t.severity] || 1) + " pts", "r"); }), rel: ".test.FAIL", relName: "failing tests" }; },
    findings: function () { return { t: "Findings", f: EV.findings.length + " findings, each mapped to SOC 2 + ISO controls", rows: EV.findings.map(function (f) { return row(f.id, f.rule, f.file ? f.file + ":" + f.line : "project-wide", "r"); }), rel: ".finding", relName: "finding cards" }; },
    files: function () { return { t: "Files fingerprinted", f: "SHA-256 per file · commit " + esc((EV.target.git_commit || "n/a").slice(0, 10)), rows: EV.files_scanned.map(function (f) { return row("#", f.path, f.sha256.slice(0, 10) + "…"); }), rel: ".chain .link", relName: "evidence links" }; }
  };
  function sevProof(sev) {
    return function () {
      var a = app.filter(function (t) { return t.severity === sev; });
      return { t: sev.charAt(0).toUpperCase() + sev.slice(1) + " tier", f: a.length + " test" + (a.length === 1 ? "" : "s") + " × " + W[sev] + " pts each",
        rows: a.map(function (t) { return row(t.status === "PASS" ? "✓" : "✕", t.id, t.status === "PASS" ? "+" + W[sev] : "−" + W[sev], t.status === "PASS" ? "g" : "r"); }),
        note: a.length ? "" : "No applicable tests at this severity", rel: null };
    };
  }

  // attach to the numbers on the Report tab
  var gnum = $(".gauge .num"); if (gnum) gnum.setAttribute("data-proof", "score");
  var kpis = $$(".kpi"), kkeys = ["pass", "fail", "findings", "files"];
  kpis.forEach(function (k, i) { if (kkeys[i]) k.setAttribute("data-proof", kkeys[i]); });
  $$(".sevrow").forEach(function (r) { var name = $(".name", r); if (name) { PROOFS["sev-" + name.textContent] = sevProof(name.textContent); $(".pts", r).setAttribute("data-proof", "sev-" + name.textContent); } });

  var pop = document.createElement("div"); pop.className = "proof"; pop.setAttribute("role", "tooltip"); document.body.appendChild(pop);
  var active = null, pinned = false;
  function scramble(el) {
    if (RM) return;
    var tgt = el.querySelector("[data-count]") || (el.matches("[data-count]") ? el : null); if (!tgt) return;
    var fin = tgt.getAttribute("data-count"), t0 = performance.now();
    (function f(t) {
      if (t - t0 < 380) { tgt.textContent = String(Math.floor(Math.random() * Math.pow(10, fin.length))); requestAnimationFrame(f); }
      else tgt.textContent = fin;
    })(t0);
  }
  function place(el) {
    var r = el.getBoundingClientRect(), pw = pop.offsetWidth, ph = pop.offsetHeight, gap = 12;
    var x = Math.min(Math.max(12, r.left + r.width / 2 - pw / 2), innerWidth - pw - 12);
    var y = r.bottom + gap + ph < innerHeight ? r.bottom + gap : Math.max(12, r.top - gap - ph);
    pop.style.left = x + "px"; pop.style.top = y + "px";
  }
  function clearTrace() { $$(".traced").forEach(function (e) { e.classList.remove("traced"); }); $$(".proofing").forEach(function (e) { e.classList.remove("proofing"); }); }
  function show(el) {
    var p = PROOFS[el.getAttribute("data-proof")](); if (!p) return;
    active = el; clearTrace(); el.classList.add("proofing");
    var rel = p.rel ? $$(p.rel) : [];
    rel.forEach(function (e) { e.classList.add("traced"); });
    var rows = p.rows.slice(0, 7), more = p.rows.length - rows.length;
    pop.innerHTML = '<div class="ph"><span>⌖ PROOF</span><span>' + (pinned ? "PINNED · ESC" : "TRACEABLE TO EVIDENCE.JSON") + "</span></div>" +
      '<div class="pt">' + esc(p.t) + '</div><div class="pf">' + p.f + "</div>" +
      (rows.length ? '<div class="rows">' + rows.map(function (r, i) { return '<div class="pr" style="animation-delay:' + i * 0.04 + 's"><span class="' + r[3] + '">' + esc(r[0]) + "</span><span>" + esc(r[1]) + "</span><span>" + esc(r[2]) + "</span></div>"; }).join("") + (more > 0 ? '<div class="pn">…and ' + more + " more</div>" : "") + "</div>" : "") +
      (p.note ? '<div class="pn">' + esc(p.note) + "</div>" : "") +
      (rel.length ? '<div class="pn">' + (pinned ? "↓ jumped to " : "Click to jump to ") + "<b>" + rel.length + " " + p.relName + "</b></div>" : "");
    pop.classList.toggle("pinned", pinned);
    place(el); pop.classList.add("on");
    return rel;
  }
  function hide() { pop.classList.remove("on", "pinned"); clearTrace(); active = null; pinned = false; }

  document.addEventListener("mouseover", function (e) {
    if (pinned) return;
    var el = e.target.closest && e.target.closest("[data-proof]");
    if (el && el !== active && el.closest(".panel.on")) { show(el); scramble(el); }
    else if (!el && active) hide();
  });
  document.addEventListener("click", function (e) {
    var el = e.target.closest && e.target.closest("[data-proof]");
    if (!el) { if (pinned && !pop.contains(e.target)) hide(); return; }
    pinned = true; var rel = show(el) || [];
    if (rel.length) {
      setTimeout(function () {
        rel[0].scrollIntoView({ behavior: RM ? "auto" : "smooth", block: "center" });
        rel.forEach(function (r) { r.classList.remove("flashy"); void r.offsetWidth; r.classList.add("flashy"); });
        pop.classList.remove("on"); clearTrace(); rel.forEach(function (r) { r.classList.add("traced"); });
        setTimeout(function () { if (pinned) hide(); }, 2600);
      }, 900);
    }
  });
  document.addEventListener("keydown", function (e) { if (e.key === "Escape") hide(); });
  addEventListener("scroll", function () { if (active && !pinned) hide(); }, { passive: true });
  document.addEventListener("tabshow", hide);
})();
