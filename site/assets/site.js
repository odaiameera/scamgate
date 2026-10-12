/* scamgate site behaviour. No dependencies. Everything shown comes from window.SCAMGATE_DEMO. */
(() => {
  "use strict";
  const D = window.SCAMGATE_DEMO;
  const $ = (s, el = document) => el.querySelector(s);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ---------------- copy buttons ---------------- */
  document.addEventListener("click", async (e) => {
    const b = e.target.closest(".copy");
    if (!b) return;
    const src = b.dataset.copy ? $(b.dataset.copy) : b.parentElement.querySelector("code");
    const text = (src?.innerText || "").replace(/^\$ /gm, "").trim();
    try { await navigator.clipboard.writeText(text); } catch { return; }
    const old = b.textContent; b.textContent = "Copied"; b.classList.add("done");
    setTimeout(() => { b.textContent = old; b.classList.remove("done"); }, 1400);
  });
  document.querySelectorAll("pre.code").forEach((pre) => {
    if (pre.querySelector(".copy")) return;
    const b = document.createElement("button");
    b.type = "button"; b.className = "copy"; b.textContent = "Copy";
    b.addEventListener("click", async () => {
      const code = pre.querySelector("code") || pre;
      try { await navigator.clipboard.writeText(code.innerText.trim()); } catch { return; }
      b.textContent = "Copied"; b.classList.add("done");
      setTimeout(() => { b.textContent = "Copy"; b.classList.remove("done"); }, 1400);
    });
    pre.appendChild(b);
  });

  if (!D) return;

  /* ---------------- hero: gate log ---------------- */
  const log = $("#gate-log");
  if (log) {
    const target = (h) => {
      const i = h.input || {};
      if (i.url) return i.url;
      if (i.urls) return i.urls.join(" ");
      if (i.command) return i.command;
      if (i.path) return i.path;
      return JSON.stringify(i);
    };
    const verdictOf = (o) => {
      if (o.hookSpecificOutput) return o.hookSpecificOutput.permissionDecision === "deny" ? "block" : "approve";
      return o.action || "pass";
    };
    const label = { block: "deny", approve: "ask", pass: "allow" };
    const messageOf = (o) => o.message || o.hookSpecificOutput?.permissionDecisionReason || "No objection: the hook prints {} and the call runs.";
    let timers = [];
    const play = () => {
      timers.forEach(clearTimeout); timers = [];
      log.innerHTML = D.hook.map((h, i) => {
        const v = verdictOf(h.output);
        return `<li data-v="${v}">
          <button class="row" type="button" aria-expanded="false">
            <span class="n">${String(i + 1).padStart(2, "0")}</span>
            <span class="what"><span class="tool">${esc(h.tool)}<small>${h.dialect === "claude" ? "Claude Code" : "Hermes"}</small></span>
              <span class="tgt">${esc(target(h))}</span></span>
            <span class="stamp ${v}">${label[v]}</span>
          </button>
          <div class="why">${esc(messageOf(h.output))}<details><summary>Raw hook output</summary><pre>${esc(JSON.stringify(h.output, null, 1))}</pre></details></div>
        </li>`;
      }).join("");
      [...log.children].forEach((li, i) => {
        if (reduced) { li.classList.add("in"); return; }
        timers.push(setTimeout(() => li.classList.add("in"), 250 + i * 420));
      });
    };
    log.addEventListener("click", (e) => {
      const row = e.target.closest(".row"); if (!row) return;
      const li = row.parentElement; const open = li.classList.toggle("open");
      row.setAttribute("aria-expanded", String(open));
    });
    $("#replay")?.addEventListener("click", play);
    play();
  }

  /* ---------------- verdict inspector ---------------- */
  const cases = $("#cases"), panel = $("#verdict");
  if (cases && panel) {
    const items = [
      ...D.urls.map((u) => ({ kind: "Link", title: u.input, sub: u.intent ? `intent: “${u.intent}”` : "check_url", v: u,
        cmd: `scamgate check-url "${u.input}"${u.intent ? ` --intent "${u.intent}"` : ""}` })),
      ...D.payments.map((p) => ({ kind: "Payment", title: `${p.input.amount} ${p.input.currency} → ${p.input.payee_name}`,
        sub: `${p.input.method.replace("_", " ")}${p.input.context_text ? ` · “${p.input.context_text}”` : ""}`, v: p, cmd: "check_payment(...)" })),
    ];
    const th = D.thresholds;
    cases.innerHTML = `<h3>Links</h3>` + items.map((it, i) =>
      `${i === D.urls.length ? "<h3>Payments</h3>" : ""}<button type="button" role="tab" id="case-${i}" aria-controls="verdict" aria-selected="false" data-i="${i}">${esc(it.title)}<small>${esc(it.sub)}</small></button>`).join("");

    const render = (i) => {
      const it = items[i], v = it.v;
      cases.querySelectorAll("button").forEach((b) => b.setAttribute("aria-selected", String(+b.dataset.i === i)));
      panel.setAttribute("aria-labelledby", `case-${i}`);
      let acc = 0;
      const segs = v.reasons.map((r) => { const from = acc; acc = Math.min(100, acc + r.weight); return acc - from; });
      const reasons = v.reasons.length
        ? v.reasons.map((r) => `<li><span class="w">${r.weight}</span><div><div class="rid">${esc(r.rule)}</div><p>${esc(r.text)}</p></div></li>`).join("")
        : `<li><span class="w" style="visibility:hidden">0</span><div><span class="none">No rule fired. That means no known red flags, not “safe”.</span></div></li>`;
      const raw = { decision: v.decision, risk_score: v.score, reasons: v.reasons.map((r) => ({ rule_id: r.rule, weight: r.weight, explanation: r.text })), summary: v.summary };
      panel.innerHTML = `
        <div class="v-top"><div class="v-dec ${v.decision}">${v.decision}</div>
          <div class="v-score"><b>${v.score}</b>/ 100</div></div>
        <div class="v-input"><span>${it.kind === "Link" ? "$ " : ""}</span>${esc(it.cmd)}</div>
        <div class="track" aria-label="Score ${v.score} of 100">
          <span class="zone a">allow</span><span class="zone k">ask</span><span class="zone d">deny</span>
          <div class="rail">${segs.map((w) => `<span class="seg" style="width:${w}%"></span>`).join("")}</div>
          <div class="zones" aria-hidden="true"><i style="width:${th.ask}%"></i><i style="width:${th.deny - th.ask}%"></i><i style="width:${100 - th.deny}%"></i></div>
          <span class="mark-score ${v.decision}" style="left:${Math.max(.8, Math.min(99.2, v.score))}%" aria-hidden="true"></span><span class="tick" style="left:${th.ask}%"></span><span class="lab" style="left:${th.ask}%">${th.ask}</span>
          <span class="tick" style="left:${th.deny}%"></span><span class="lab" style="left:${th.deny}%">${th.deny}</span>
        </div>
        <ul class="reasons">${reasons}</ul>
        <div class="v-foot"><small>Points are capped at 100.${v.reasons.length > 1 ? " The bar shows each rule's share." : ""}</small>
          <button class="btn" type="button" id="toggle-raw" aria-expanded="false">Show JSON</button></div>
        <pre class="raw" hidden>${esc(JSON.stringify(raw, null, 2))}</pre>`;
      $("#toggle-raw", panel).addEventListener("click", (e) => {
        const pre = $(".raw", panel); pre.hidden = !pre.hidden;
        e.currentTarget.textContent = pre.hidden ? "Show JSON" : "Hide JSON";
        e.currentTarget.setAttribute("aria-expanded", String(!pre.hidden));
      });
    };
    cases.addEventListener("click", (e) => { const b = e.target.closest("button[data-i]"); if (b) render(+b.dataset.i); });
    cases.addEventListener("keydown", (e) => {
      if (!["ArrowDown", "ArrowUp", "ArrowRight", "ArrowLeft"].includes(e.key)) return;
      const cur = +(document.activeElement?.dataset.i ?? 0);
      const next = (cur + (e.key === "ArrowDown" || e.key === "ArrowRight" ? 1 : -1) + items.length) % items.length;
      e.preventDefault(); render(next); $(`#case-${next}`)?.focus();
    });
    render(0);
  }

  /* ---------------- docs: rules table from the real config ---------------- */
  const rulesTbl = $("#rules-table");
  if (rulesTbl && D.rules) {
    const fmt = (c) => Object.entries(c).map(([k, v]) => typeof v === "object"
      ? Object.entries(v).map(([a, b]) => `${a} ${b}`).join(", ") : `${k === "weight" ? "" : k.replace(/_weight$/, "").replace(/_/g, " ") + " "}${v}`).join(" · ");
    rulesTbl.innerHTML = `<thead><tr><th>Rule</th><th>Points</th><th>What it catches</th></tr></thead><tbody>` +
      D.rules.map((r) => `<tr class="${r.enabled ? "" : "off"}"><td><code>${esc(r.id)}</code></td><td>${esc(fmt(r.config))}${r.enabled ? "" : " · off"}</td><td>${esc(r.doc)}</td></tr>`).join("") + `</tbody>`;
  }
  document.querySelectorAll("[data-threshold]").forEach((el) => { el.textContent = D.thresholds[el.dataset.threshold]; });

  /* ---------------- docs: scrollspy ---------------- */
  const toc = $(".toc");
  if (toc && "IntersectionObserver" in window) {
    const links = [...toc.querySelectorAll('a[href^="#"]')];
    const map = new Map(links.map((a) => [a.getAttribute("href").slice(1), a]));
    const io = new IntersectionObserver((entries) => {
      entries.forEach((en) => {
        if (!en.isIntersecting) return;
        links.forEach((a) => a.classList.remove("active"));
        map.get(en.target.id)?.classList.add("active");
      });
    }, { rootMargin: "-20% 0px -70% 0px" });
    map.forEach((_, id) => { const s = document.getElementById(id); if (s) io.observe(s); });
  }
})();
