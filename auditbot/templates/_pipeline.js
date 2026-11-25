/* Agent Pipeline: a scripted, mocked run of the PR compliance autopilot.
   Static scores are real (computed from this scan's control tests, mirroring demo/risky_change.py and `auditbot fix`);
   the PR, agent messages, CI jobs and Prometheus telemetry are illustrative. */
(function () {
  "use strict";
  var EV = JSON.parse(document.getElementById("ev").textContent);
  var W = { critical: 10, high: 5, medium: 2, low: 1 };
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var esc = function (s) { return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); };
  var pyRound = function (x) { var f = Math.floor(x); return Math.abs(x - f - 0.5) < 1e-9 ? (f % 2 ? f + 1 : f) : Math.round(x); };
  var colOf = function (s) { return s >= 85 ? "var(--pass)" : s >= 60 ? "var(--med)" : "var(--fail)"; };

  /* ---------- real static scores ---------- */
  var T = {}; EV.control_tests.forEach(function (t) { T[t.id] = t; });
  var FALLBACK = {
    "NET-OPEN-ADMIN": { title: "Admin ports (SSH/RDP) not exposed to the internet", severity: "critical", soc2: ["CC6.6"], iso27001: ["A.8.20", "A.8.22"] },
    "DB-ENCRYPTION": { title: "Databases encrypted at rest", severity: "high", soc2: ["CC6.1", "CC6.7"], iso27001: ["A.8.24"] },
    "SECRET-HARDCODED": { title: "No hardcoded credentials in source or config", severity: "critical", soc2: ["CC6.1"], iso27001: ["A.5.17", "A.8.24"] },
    "LOG-AUDIT-TRAIL": { title: "Audit logging enabled (CloudTrail)", severity: "high", soc2: ["CC7.2", "CC7.3"], iso27001: ["A.8.15", "A.8.16"] }
  };
  var info = function (id) { return T[id] || FALLBACK[id]; };
  var applicable = function (id) { return T[id] && T[id].status !== "N/A"; };
  function scoreWith(over) {
    var tot = 0, got = 0;
    EV.control_tests.forEach(function (t) {
      if (t.status === "N/A") return;
      var w = W[t.severity] || 1, s = over[t.id] || t.status; tot += w; if (s === "PASS") got += w;
    });
    return tot ? pyRound(100 * got / tot) : 100;
  }
  var RISKY = [["NET-OPEN-ADMIN", "infra/main.tf", "SSH (22) open to 0.0.0.0/0"], ["DB-ENCRYPTION", "infra/main.tf", "storage_encrypted = false"], ["SECRET-HARDCODED", "app/settings.py", "AWS access key in source"]];
  var FIXABLE = ["NET-OPEN-ADMIN", "DB-ENCRYPTION", "SECRET-HARDCODED", "LOG-AUDIT-TRAIL"];   // ids with offline fix templates in fixer.py
  var riskyOver = {}, fixOver = {};
  RISKY.forEach(function (r) { if (applicable(r[0])) riskyOver[r[0]] = "FAIL"; });
  FIXABLE.forEach(function (id) { if (applicable(id)) fixOver[id] = "PASS"; });
  var S0 = EV.summary.readiness_score, S1 = scoreWith(riskyOver), S2 = scoreWith(fixOver);
  var resolved = FIXABLE.filter(function (id) { return applicable(id) && (riskyOver[id] || T[id].status === "FAIL"); }).length;

  /* ---------- stages / rail ---------- */
  var STAGES = [
    { ic: "⇣", n: "PR intake", w: "webhook" },
    { ic: "⌕", n: "Compliance analyst", w: "agent" },
    { ic: "✎", n: "Remediation agent", w: "code + tests" },
    { ic: "⚙", n: "CI/CD pipeline", w: "GitHub Actions" },
    { ic: "◉", n: "Telemetry sub-agent", w: "Prometheus" },
    { ic: "Δ", n: "Delta analyst", w: "main vs PR" },
    { ic: "⚖", n: "Decision agent", w: "merge gate" }
  ];
  var rail = $("#rail");
  rail.innerHTML = STAGES.map(function (s, i) {
    return (i ? '<div class="wire"></div>' : "") + '<div class="node" data-i="' + i + '"><div class="nic"><span>' + s.ic +
      '</span><svg viewBox="0 0 70 70"><circle cx="35" cy="35" r="33"/></svg></div><b>' + s.n + "</b><small>" + s.w + '</small><em class="nt"></em></div>';
  }).join("");
  var nodes = rail.querySelectorAll(".node"), wires = rail.querySelectorAll(".wire");
  var body = $("#svBody"), plog = $("#plog"), views = [], cur = -1, live = false;

  function setNode(i, state, note) {
    nodes[i].className = "node " + state + (nodes[i].classList.contains("sel") ? " sel" : "");
    if (note != null) nodes[i].querySelector(".nt").textContent = note;
    if (state === "run") {
      if (wires[i - 1]) wires[i - 1].className = "wire done";
      if (wires[i]) wires[i].className = "wire flow";
      nodes[i].scrollIntoView && rail.scrollTo({ left: nodes[i].offsetLeft - rail.clientWidth / 2 + 56, behavior: "smooth" });
    }
  }
  function showView(i) {
    views.forEach(function (v, j) { if (v) v.hidden = j !== i; });
    Array.prototype.forEach.call(nodes, function (n, j) { n.classList.toggle("sel", j === i); });
    $("#svTitle").textContent = "STAGE " + (i + 1) + "/" + STAGES.length + " · " + STAGES[i].n.toUpperCase();
    var m = $("#svMode"), isLive = live && i === cur;
    m.textContent = isLive ? "● LIVE" : "◀ REPLAY"; m.className = "live" + (isLive ? "" : " rep");
  }
  function view(i, html) {
    var d = document.createElement("div"); d.className = "svx"; d.innerHTML = html;
    views[i] = d; body.appendChild(d); cur = i; showView(i); return d;
  }
  rail.addEventListener("click", function (e) { var n = e.target.closest(".node"); if (n && views[+n.dataset.i]) showView(+n.dataset.i); });

  /* ---------- run control ---------- */
  var runId = 0, speed = 1, scen = "A", clock = 0, started = false, STOP = {};
  function sleep(id, ms) {
    clock += ms;
    return new Promise(function (res, rej) { setTimeout(function () { if (id === runId) res(); else rej(STOP); }, FX.RM ? 0 : ms / speed); });
  }
  var AG = { github: "github", router: "orchestrator", analyst: "compliance-analyst", remed: "remediation-agent", ci: "ci", tel: "telemetry-watcher", delta: "delta-analyst", gate: "decision-agent" };
  function log(ag, html, kind) {
    var d = document.createElement("div"); d.className = "ll " + (kind || "");
    var t = clock / 1000, ts = (t < 10 ? "0" : "") + t.toFixed(1);
    d.innerHTML = '<span class="ts">' + ts + 's</span><span class="ag ' + ag + '">' + AG[ag] + "</span>" + html;
    plog.appendChild(d); plog.scrollTop = plog.scrollHeight;
  }
  function countTo(el, from, to, ms, suffix) {
    var t0 = performance.now(), dur = FX.RM ? 0 : ms / speed;
    (function f(t) { var k = dur ? Math.min(1, (t - t0) / dur) : 1, v = Math.round(from + (to - from) * (1 - Math.pow(1 - k, 3)));
      el.textContent = (suffix === "±" ? (v > 0 ? "+" : v < 0 ? "−" : "±") + Math.abs(v) : v + (suffix || "")); if (k < 1) requestAnimationFrame(f); })(t0);
  }
  var lineCls = function (l) { return l[0] === "+" ? "add" : l[0] === "-" ? "del" : "ctx"; };
  function typeLines(id, pre, lines, per) {
    return lines.reduce(function (p, l) {
      return p.then(function () { var s = document.createElement("span"); s.className = "dl " + lineCls(l); s.textContent = l || " "; pre.appendChild(s); pre.scrollTop = pre.scrollHeight; return sleep(id, per); });
    }, Promise.resolve());
  }
  function hl(src) {
    return String(src).replace(/[&<>]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]; }).replace(/(#[^\n]*)|("[^"\n]*")|\b(def|assert|for|in|not|import|from|all|and|return)\b/g, function (m, cm, str, kw) {
      return cm ? '<span class="cm">' + cm + "</span>" : str ? '<span class="str">' + str + "</span>" : '<span class="kw">' + kw + "</span>";
    });
  }
  function typeChars(id, pre, text) {
    var i = 0, step = 4;
    return new Promise(function (res, rej) {
      (function f() {
        i = Math.min(text.length, i + step); pre.textContent = text.slice(0, i); pre.scrollTop = pre.scrollHeight;
        if (i >= text.length) { pre.innerHTML = hl(text); res(); return; }
        sleep(id, 14).then(f, rej);
      })();
    });
  }

  /* ---------- telemetry mock data ---------- */
  var N = 60, DEP = 20;
  function rng(seed) { return function () { seed = seed + 0x6D2B79F5 | 0; var t = Math.imul(seed ^ seed >>> 15, 1 | seed); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; }; }
  function series(seed, base, noise, after, afterNoise) {
    var r = rng(seed), s = [], c = [];
    for (var i = 0; i < N; i++) {
      var b = Math.max(0, base + (r() - 0.5) * 2 * noise); s.push(b);
      if (i < DEP) { c.push(null); continue; }
      var k = Math.min(1, (i - DEP) / 3), tv = Math.max(0, after + (r() - 0.5) * 2 * afterNoise);
      c.push(b * (1 - k) + tv * k);
    }
    return [s, c];
  }
  var mean = function (a) { var v = a.filter(function (x) { return x != null; }); return v.reduce(function (x, y) { return x + y; }, 0) / v.length; };
  function panels() {
    var B = scen === "B";
    var P = [
      { t: "Logins without MFA", u: "/min", ctl: "CC6.1 · A.5.17", name: "MFA enforcement", w: 5, q: 'sum(rate(auth_login_total{mfa="false"}[5m])) * 60', d: series(11, 11, 3, 0, 0), ok: function (v) { return v < 0.5; }, f: 1 },
      { t: "Audit events delivered", u: "/min", ctl: "CC7.2 · A.8.15", name: "Audit logging", w: 5, q: "sum(rate(cloudtrail_events_delivered_total[5m])) * 60", d: series(22, 0, 0, 320, 25), ok: function (v) { return v > 50; }, f: 0 },
      { t: "DB connections without TLS", u: "", ctl: "CC6.7 · A.8.24", name: "Encryption in transit", w: 10, q: 'sum(pg_stat_ssl_connections{ssl="false"})', d: B ? series(33, 0, 0, 38, 6) : series(33, 0, 0, 0, 0), ok: function (v) { return v < 0.5; }, f: 0 },
      { t: "p95 latency", u: " ms", ctl: "A1.2 · SLO 250 ms", name: "Availability SLO", w: 2, q: "histogram_quantile(0.95, sum by (le) (rate(http_request_duration_seconds_bucket[5m]))) * 1000", d: B ? series(44, 182, 7, 412, 22) : series(44, 182, 7, 187, 7), ok: function (v) { return v < 250; }, f: 0, slo: 250 }
    ];
    P.forEach(function (p) {
      p.main = mean(p.d[0]); p.pr = mean(p.d[1].slice(DEP + 4)); p.mOk = p.ok(p.main); p.pOk = p.ok(p.pr);
      p.v = p.pOk && !p.mOk ? "good" : p.pOk ? "eq" : "bad";
      p.vt = { good: "▲ FIXED", eq: "= HEALTHY", bad: p.mOk ? "▼ REGRESSION" : "✕ STILL FAILING" }[p.v];
      p.color = { good: "#34d399", eq: "#22d3ee", bad: "#f43f5e" }[p.v];
      p.fmt = function (v) { return v.toFixed(p.f) + p.u; };
    });
    return P;
  }
  var gid = 0;
  function drawChart(svg, p, dur) {
    var s = p.d[0], c = p.d[1], Wd = 320, H = 118, pad = 6, top = 16;
    var vals = s.concat(c.filter(function (v) { return v != null; })); if (p.slo) vals.push(p.slo);
    var ymax = Math.max(1, Math.max.apply(null, vals) * 1.15);
    var X = function (i) { return pad + i * (Wd - 2 * pad) / (N - 1); }, Y = function (v) { return H - pad - v / ymax * (H - pad - top); };
    var line = function (a) { var d = "", first = true; a.forEach(function (v, i) { if (v == null) return; d += (first ? "M" : "L") + X(i).toFixed(1) + " " + Y(v).toFixed(1); first = false; }); return d; };
    var g = "gg" + (++gid), h = '<defs><linearGradient id="' + g + '" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="' + p.color + '" stop-opacity=".38"/><stop offset="1" stop-color="' + p.color + '" stop-opacity="0"/></linearGradient></defs>';
    [0.25, 0.5, 0.75, 1].forEach(function (f) { var y = (H - pad - f * (H - pad - top)).toFixed(1); h += '<line x1="' + pad + '" x2="' + (Wd - pad) + '" y1="' + y + '" y2="' + y + '" stroke="rgba(148,163,209,.09)"/>'; });
    if (p.slo) h += '<line x1="' + pad + '" x2="' + (Wd - pad) + '" y1="' + Y(p.slo).toFixed(1) + '" y2="' + Y(p.slo).toFixed(1) + '" stroke="#fbbf24" stroke-opacity=".7" stroke-dasharray="4 4"/><text class="gl" x="' + (pad + 2) + '" y="' + (Y(p.slo) - 4).toFixed(1) + '" fill="#fbbf24">SLO 250</text>';
    h += '<line x1="' + X(DEP).toFixed(1) + '" x2="' + X(DEP).toFixed(1) + '" y1="' + (top - 8) + '" y2="' + (H - pad) + '" stroke="#a78bfa" stroke-dasharray="3 3"/><text class="gl" x="' + (X(DEP) + 4).toFixed(1) + '" y="' + (top - 2) + '" fill="#a78bfa">deploy</text>';
    h += '<path class="area" d="' + line(c) + " L" + X(N - 1).toFixed(1) + " " + (H - pad) + " L" + X(DEP).toFixed(1) + " " + (H - pad) + ' Z" fill="url(#' + g + ')"/>';
    h += '<path class="draw" d="' + line(s) + '" fill="none" stroke="#7d89ab" stroke-width="1.4"/>';
    h += '<path class="draw cn" d="' + line(c) + '" fill="none" stroke="' + p.color + '" stroke-width="2.2" style="filter:drop-shadow(0 0 4px ' + p.color + ')"/>';
    svg.innerHTML = h;
    var paths = svg.querySelectorAll(".draw");
    Array.prototype.forEach.call(paths, function (pa, j) {
      var L = pa.getTotalLength() || 1; pa.style.strokeDasharray = L; pa.style.strokeDashoffset = L; pa.getBoundingClientRect();
      var d = j ? dur * (N - DEP) / N : dur, delay = j ? dur * DEP / N : 0;
      pa.style.transition = "stroke-dashoffset " + d + "ms linear " + delay + "ms"; pa.style.strokeDashoffset = 0;
    });
    setTimeout(function () { var a = svg.querySelector(".area"); if (a) a.classList.add("in"); }, dur * 0.6);
  }

  /* ---------- the PR (mirrors demo/risky_change.py) ---------- */
  var PR_TF = [' resource "aws_security_group_rule" "ssh" {', '-  description = "SSH from VPN only"', '+  description = "SSH - temp access for debugging"',
    '-  cidr_blocks = ["10.20.0.0/16"]', '+  cidr_blocks = ["0.0.0.0/0"]', " ...", ' resource "aws_db_instance" "main" {', "-  storage_encrypted   = true", "+  storage_encrypted   = false"];
  var PR_PY = [" DEBUG = False", "+", "+# TODO remove before release", '+AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"'];
  var PATCH = ["--- a/infra/main.tf", "+++ b/infra/main.tf", '-  cidr_blocks = ["0.0.0.0/0"]', '+  cidr_blocks = ["10.20.0.0/16"]   # VPN only', "-  storage_encrypted   = false",
    "+  storage_encrypted   = true", '+resource "aws_cloudtrail" "main" {', '+  name                       = "org-audit-trail"', "+  is_multi_region_trail      = true",
    "+  enable_log_file_validation = true", "+  kms_key_id                 = aws_kms_key.logs.arn", "+}", "--- a/app/settings.py", "+++ b/app/settings.py",
    '-AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"', '+AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]'];
  var TESTS = [
    "# generated by remediation-agent · guards the controls this PR touched",
    "from compliance_kit import load_plan, repo",
    "",
    "def test_no_admin_ports_open_to_internet():",
    "    for rule in load_plan().ingress_rules(port=22):",
    '        assert "0.0.0.0/0" not in rule.cidr_blocks',
    "",
    "def test_databases_encrypted_at_rest():",
    "    assert all(db.storage_encrypted for db in load_plan().rds_instances)",
    "",
    "def test_no_hardcoded_aws_keys():",
    '    assert not repo().grep(r"AKIA[0-9A-Z]{16}")',
    "",
    "def test_cloudtrail_multi_region_with_validation():",
    '    trail = load_plan().one("aws_cloudtrail")',
    "    assert trail.is_multi_region_trail and trail.enable_log_file_validation"
  ].join("\n");

  /* ---------- stage scripts ---------- */
  var tag = function (c, cls) { return '<span class="tag ' + cls + '">' + esc(c) + "</span>"; };
  var ctlTags = function (t) { return t.soc2.map(function (c) { return tag(c, "soc"); }).join("") + t.iso27001.map(function (c) { return tag(c, "iso"); }).join(""); };

  async function stPR(id) {
    setNode(0, "run");
    var v = view(0, '<div class="pr-head"><span class="pr-badge">⇡ Open</span><h3 style="margin:0">#217 · quick fix: temp SSH access for debugging</h3></div>' +
      '<p class="sub" style="margin-top:8px">dev-jordan wants to merge <code>feature/debug-access</code> → <code>main</code> · 2 files changed · <span style="color:var(--pass)">+5</span> <span style="color:var(--fail)">−3</span></p>' +
      '<div class="code"><div class="bar"><i></i><i></i><i></i>infra/main.tf</div><pre class="diff a"></pre></div>' +
      '<div class="code"><div class="bar"><i></i><i></i><i></i>app/settings.py</div><pre class="diff b"></pre></div>');
    log("github", "<b>pull_request.opened</b> #217 · dev-jordan → main");
    await sleep(id, 500);
    log("router", "webhook verified · fetching diff (2 files)");
    await typeLines(id, $(".a", v), PR_TF, 130);
    await typeLines(id, $(".b", v), PR_PY, 130);
    log("router", "PR touches IaC + app config → dispatching <b>compliance-analyst</b>");
    await sleep(id, 500);
    setNode(0, "ok", "#217");
  }

  async function stScan(id) {
    setNode(1, "run");
    var v = view(1, '<div class="vs"><div><div class="big" style="color:' + colOf(S0) + '">' + S0 + '%</div><small>MAIN</small></div><div class="arrow">→</div>' +
      '<div><div class="big sc" style="color:' + colOf(S0) + '">' + S0 + "%</div><small>PR #217 HEAD</small></div></div>" +
      '<div class="sub">New findings vs. main</div><div class="fl"></div><div class="bn"></div>');
    log("analyst", "checking out PR head · " + EV.files_scanned.length + " config files · " + EV.control_tests.length + " control tests");
    await sleep(id, 700);
    log("analyst", "control IDs come from the deterministic catalog (controls.yaml), never from the model");
    await sleep(id, 500);
    var fl = $(".fl", v), found = RISKY.filter(function (r) { return riskyOver[r[0]]; });
    for (var i = 0; i < found.length; i++) {
      var r = found[i], t = info(r[0]);
      fl.insertAdjacentHTML("beforeend", '<div class="fr"><span class="sev ' + t.severity + '">' + t.severity + "</span><b>" + esc(t.title) + '</b><span class="loc">' + r[1] + " · " + esc(r[2]) + " · " + ctlTags(t) + "</span></div>");
      log("analyst", "NEW " + t.severity.toUpperCase() + " <b>" + r[0] + "</b> " + r[1] + " (" + t.soc2.join(", ") + ")", "bad");
      await sleep(id, 650);
    }
    var sc = $(".sc", v); sc.style.color = colOf(S1); countTo(sc, S0, S1, 1200, "%"); sc.classList.add("glitch");
    FX.shake($(".vs", v));
    await sleep(id, 1100);
    $(".bn", v).innerHTML = '<div class="banner bad">⛔ Merge gate: BLOCK · readiness ' + S0 + "% → " + S1 + "% (−" + (S0 - S1) + " pts) · " + found.length + " new finding" + (found.length === 1 ? "" : "s") + "</div>";
    log("analyst", "gate=BLOCK (" + S0 + "% → " + S1 + "%) · handing findings + file context to <b>remediation-agent</b>", "bad");
    await sleep(id, 700);
    setNode(1, "fail", S1 + "%");
  }

  async function stFix(id) {
    setNode(2, "run");
    var v = view(2, '<div class="code"><div class="bar"><i></i><i></i><i></i>patch · infra/main.tf, app/settings.py</div><pre class="diff p"></pre></div>' +
      '<div class="code"><div class="bar"><i></i><i></i><i></i>tests/test_compliance_iac.py<span class="new">NEW</span></div><pre class="py t"></pre></div><div class="bn"></div>');
    log("remed", "drafting minimal patch · claude-opus-5-5 · JSON-schema output");
    await sleep(id, 700);
    await typeLines(id, $(".p", v), PATCH, 110);
    log("remed", "patch applied in memory → re-scanning…");
    await sleep(id, 700);
    log("remed", "verified: " + resolved + " findings resolved, 0 new · " + S1 + "% → " + S2 + "%", "good");
    log("remed", "writing regression tests so these controls can't silently break again");
    await typeChars(id, $(".t", v), TESTS);
    $(".bn", v).innerHTML = '<div class="banner good">✓ Verified fix · ' + S1 + "% → " + S2 + "% · 4 regression tests · pushed commit <code>9f3c2e1</code></div>";
    log("remed", "pushed 9f3c2e1 to feature/debug-access", "good");
    await sleep(id, 500);
    setNode(2, "ok", "+4 tests");
  }

  async function stCI(id) {
    setNode(3, "run");
    var JOBS = [["checkout", "actions/checkout@v4", 600], ["lint", "tflint · ruff", 900], ["unit tests", "pytest -q → 28 passed", 1500],
      ["compliance gate", "auditbot check --base main → " + S2 + "% ≥ " + S0 + "%", 1200], ["terraform plan", "+1 to add · 2 to change · 0 to destroy", 1000], ["deploy canary", "staging · 10% of traffic", 1300]];
    var v = view(3, '<p class="sub">workflow <code>compliance-gate.yml</code> · run #1043 · commit <code>9f3c2e1</code></p><div class="jobs">' +
      JOBS.map(function (j) { return '<div class="job"><span class="ji"></span><span class="jn">' + j[0] + '</span><span class="jd">' + esc(j[1]) + '</span><span class="jt"></span><span class="jb"><i></i></span></div>'; }).join("") + '</div><div class="bn"></div>');
    var rows = v.querySelectorAll(".job");
    for (var i = 0; i < JOBS.length; i++) {
      var row = rows[i], bar = $(".jb i", row);
      row.classList.add("run"); log("ci", "▶ " + JOBS[i][0]);
      bar.style.transitionDuration = (FX.RM ? 0 : JOBS[i][2] / speed) + "ms"; bar.getBoundingClientRect(); bar.style.width = "100%";
      await sleep(id, JOBS[i][2]);
      row.classList.remove("run"); row.classList.add("ok"); $(".jt", row).textContent = (JOBS[i][2] / 1000).toFixed(1) + "s";
      log("ci", "✓ " + JOBS[i][0] + " · " + esc(JOBS[i][1]), "good");
    }
    $(".bn", v).innerHTML = '<div class="banner good">✓ 6/6 checks passed · canary <code>v2.14.0-pr217</code> live on 10% of staging</div>';
    await sleep(id, 500);
    setNode(3, "ok", "6/6");
  }

  var P = [];
  async function stTel(id) {
    setNode(4, "run"); P = panels();
    var v = view(4, '<p class="sub">sub-agent <b>telemetry-watcher</b> · Prometheus <code>prom.staging:9090</code> · window −10m … +20m around deploy</p><div class="panels">' +
      P.map(function (p) { return '<div class="gp"><div class="gt"><span>' + p.t + "</span>" + tag(p.ctl, "soc") + '</div><div class="gq">' + esc(p.q) + '</div><svg viewBox="0 0 320 118"></svg><div class="gs"><span>main <b>' + p.fmt(p.main) + "</b> → canary <b>" + p.fmt(p.pr) + '</b></span><span class="vchip ' + p.v + '">' + p.vt + "</span></div></div>"; }).join("") +
      '</div><div class="glegend"><span><i style="background:#7d89ab"></i>main (stable)</span><span><i style="background:var(--cyan)"></i>PR #217 canary</span></div>');
    log("router", "spawning sub-agent <b>telemetry-watcher</b> · scope: canary pods · 20m window");
    await sleep(id, 600);
    var gps = v.querySelectorAll(".gp");
    for (var i = 0; i < P.length; i++) {
      log("tel", "PromQL <span style=\"color:#5f6b8c\">" + esc(P[i].q.length > 60 ? P[i].q.slice(0, 58) + "…" : P[i].q) + "</span>");
      drawChart($("svg", gps[i]), P[i], FX.RM ? 0 : 1700 / speed);
      await sleep(id, 1500);
      $(".vchip", gps[i]).classList.add("in");
      var p = P[i];
      log("tel", p.name + ": main " + p.fmt(p.main) + " → canary " + p.fmt(p.pr) + " · " + p.vt, p.v === "bad" ? "bad" : p.v === "good" ? "good" : "");
      await sleep(id, 350);
    }
    var bad = P.filter(function (p) { return p.v === "bad"; }).length;
    if (bad) log("tel", "⚠ " + bad + " runtime anomal" + (bad > 1 ? "ies" : "y") + " on canary (e.g. app connects with sslmode=disable)", "warn");
    await sleep(id, 400);
    setNode(4, bad ? "warn" : "ok", bad ? bad + " anomalies" : "4/4 healthy");
  }

  async function stDelta(id) {
    setNode(5, "run");
    var tot = 0, m = 0, pr = 0;
    P.forEach(function (p) { tot += p.w; if (p.mOk) m += p.w; if (p.pOk) pr += p.w; });
    var R0 = pyRound(100 * m / tot), R1 = pyRound(100 * pr / tot), dS = S2 - S0, dR = R1 - R0;
    var v = view(5, '<div class="dgrid">' +
      '<div class="dbox"><div class="dh">STATIC READINESS · IaC</div><div class="dr">main ' + S0 + '% → PR ' + S2 + '%</div><div class="dd ds" style="color:' + (dS >= 0 ? "var(--pass)" : "var(--fail)") + '">±0</div></div>' +
      '<div class="dbox"><div class="dh">RUNTIME POSTURE · TELEMETRY</div><div class="dr">main ' + R0 + '% → PR ' + R1 + '%</div><div class="dd dr2" style="color:' + (dR >= 0 ? "var(--pass)" : "var(--fail)") + '">±0</div></div></div>' +
      '<div class="dt"><div class="r h"><span>CONTROL · EVIDENCE</span><span>MAIN</span><span>PR #217</span><span>Δ</span></div></div>');
    log("delta", "diffing control evidence: main vs PR head (static + runtime)");
    countTo($(".ds", v), 0, dS, 1100, "±"); countTo($(".dr2", v), 0, dR, 1300, "±");
    await sleep(id, 900);
    var dt = $(".dt", v);
    for (var i = 0; i < P.length; i++) {
      var p = P[i], arrow = p.pOk === p.mOk ? "=" : p.pOk ? "▲" : "▼", ac = p.pOk === p.mOk ? "var(--muted)" : p.pOk ? "var(--pass)" : "var(--fail)";
      dt.insertAdjacentHTML("beforeend", '<div class="r"><span>' + p.name + "<small>" + p.ctl + " · " + p.t.toLowerCase() + '</small></span><span class="' + (p.mOk ? "ok" : "no") + '">' + (p.mOk ? "✓ " : "✕ ") + p.fmt(p.main) +
        '</span><span class="' + (p.pOk ? "ok" : "no") + '">' + (p.pOk ? "✓ " : "✕ ") + p.fmt(p.pr) + '</span><span class="d" style="color:' + ac + '">' + arrow + "</span></div>");
      log("delta", p.ctl.split(" · ")[0] + " " + p.name + ": " + (p.mOk ? "PASS" : "FAIL") + " → " + (p.pOk ? "PASS" : "FAIL") + " " + arrow, p.pOk === p.mOk ? "" : p.pOk ? "good" : "bad");
      await sleep(id, 550);
    }
    var reg = P.filter(function (p) { return p.mOk && !p.pOk; });
    log("delta", "static Δ " + (dS >= 0 ? "+" : "") + dS + " pts · runtime Δ " + (dR >= 0 ? "+" : "") + dR + " pts · regressions: " + reg.length, reg.length ? "bad" : "good");
    await sleep(id, 500);
    setNode(5, reg.length ? "fail" : "ok", "Δ " + (dR >= 0 ? "+" : "") + dR);
    return { dS: dS, dR: dR, reg: reg };
  }

  async function stGate(id, d) {
    setNode(6, "run");
    log("gate", "weighing static Δ, runtime Δ and regressions against policy…");
    await sleep(id, 1200);
    var ok = !d.reg.length && d.dS >= 0 && d.dR >= 0;
    var reasons = ok ? [
      "Static readiness " + S0 + "% → " + S2 + "% (" + (d.dS >= 0 ? "+" : "") + d.dS + " pts), " + resolved + " findings resolved, 0 introduced",
      "Runtime posture +" + d.dR + " pts: MFA bypass logins eliminated, audit trail delivering events",
      "No SLO or encryption regressions on canary",
      "4 regression tests added for the controls this PR touched"
    ] : [
      "Static readiness improved (" + S0 + "% → " + S2 + "%) but runtime posture fell " + Math.abs(d.dR) + " pts",
      d.reg.map(function (p) { return p.name + " (" + p.ctl.split(" · ")[0] + "): " + p.fmt(p.main) + " → " + p.fmt(p.pr); }).join(" · "),
      "Canary rolled back automatically; production untouched",
      "Remediation-agent re-assigned: enforce sslmode=require in the DB client"
    ];
    var v = view(6, '<div class="vbig ' + (ok ? "good" : "bad") + '"><div class="vb">' + (ok ? "APPROVED ✓" : "BLOCKED ✕") + "</div><p>" +
      (ok ? "PR #217 merged to main · canary promoted to 100%" : "PR #217 marked “changes requested” · canary rolled back") + '</p></div><ul class="reasons">' +
      reasons.map(function (r, i) { return '<li style="animation-delay:' + (i * 0.12) + 's">' + esc(r) + "</li>"; }).join("") + "</ul>" +
      '<div class="prc"><div class="ph"><b>auditus[bot]</b> commented on #217</div><div class="pb">' +
      (ok ? "✅ <b>Compliance gate passed.</b> Readiness " + S2 + "% (baseline " + S0 + "%). Evidence: <code>evidence.json</code> (SHA-256 per file, commit 9f3c2e1)."
          : "⛔ <b>Compliance gate failed at runtime.</b> CC6.7 encryption in transit regressed on canary. Static evidence alone isn't enough: please fix and re-run.") +
      "</div></div>");
    var c = FX.centerOf($(".vb", v));
    if (ok) { FX.confetti(c.x, c.y, 200, 1.1); log("gate", "APPROVE · merged #217 · evidence attached", "good"); }
    else { FX.flash("rgba(244,63,94,.6)"); FX.shake($(".vbig", v)); log("gate", "BLOCK · changes requested on #217 · canary rolled back", "bad"); }
    setNode(6, ok ? "ok" : "fail", ok ? "merged" : "blocked");
    FX.toast(ok ? "✅ PR #217 approved" : "⛔ PR #217 blocked", ok ? "All agents agree: merged with evidence attached." : "Runtime telemetry caught what static analysis couldn't.", ok ? "good" : "bad");
  }

  function reset() {
    runId++; clock = 0; views = []; body.innerHTML = ""; plog.innerHTML = ""; cur = -1;
    Array.prototype.forEach.call(nodes, function (n) { n.className = "node"; n.querySelector(".nt").textContent = ""; });
    Array.prototype.forEach.call(wires, function (w) { w.className = "wire"; });
    $("#pBar").style.width = "0";
  }
  async function play() {
    reset(); started = true; live = true;
    var id = runId, steps = [stPR, stScan, stFix, stCI, stTel, stDelta], d;
    $("#pRun").textContent = "■ Restart";
    try {
      for (var i = 0; i < steps.length; i++) { d = await steps[i](id); $("#pBar").style.width = ((i + 1) / 7 * 100) + "%"; }
      await stGate(id, d); $("#pBar").style.width = "100%";
      live = false; showView(6); $("#pRun").textContent = "▶ Run again";
    } catch (e) { if (e !== STOP) { console.error(e); } }
  }

  $("#pRun").addEventListener("click", play);
  $("#pSpeed").addEventListener("click", function () { speed = speed === 1 ? 2 : speed === 2 ? 4 : 1; this.textContent = speed + "×"; });
  Array.prototype.forEach.call(document.querySelectorAll("#pScen button"), function (b) {
    b.addEventListener("click", function () {
      Array.prototype.forEach.call(document.querySelectorAll("#pScen button"), function (x) { x.classList.toggle("on", x === b); });
      scen = b.dataset.s; play();
    });
  });
  document.addEventListener("tabshow", function (e) {
    if (e.detail !== "pipeline" || started) return;
    started = true;
    (function wait() { var boot = document.getElementById("boot"); if (boot && !boot.classList.contains("done")) setTimeout(wait, 150); else setTimeout(play, 500); })();
  });
})();
