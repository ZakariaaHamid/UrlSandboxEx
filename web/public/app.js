// UrlSandboxEx web UI behaviour: theme, tabs, filters, search, selection, triage,
// copy, live queue, batch and job progress.
// Values from scanned pages only ever reach the DOM as textContent or via
// server-escaped HTML.
document.documentElement.classList.add("js");

(() => {
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => Array.from(el.querySelectorAll(s));
  const defang = (u) => String(u || "").replace(/^http/i, "hxxp").replace(/\./g, "[.]");
  const store = { get(k) { try { return JSON.parse(localStorage.getItem(k)); } catch (e) { return null; } }, set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) { /* unavailable */ } } };
  const el = (tag, props = {}, ...kids) => { const e = Object.assign(document.createElement(tag), props); for (const k of kids) e.append(k); return e; };
  const secs = (ms) => { const s = Math.max(0, Math.round(ms / 1000)); return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`; };
  const ago = (t) => { const s = Math.round((Date.now() - new Date(t)) / 1000); return s < 60 ? `${s}s ago` : s < 3600 ? `${Math.round(s / 60)}m ago` : s < 86400 ? `${Math.round(s / 3600)}h ago` : new Date(t).toISOString().slice(0, 16).replace("T", " "); };
  const typing = () => /INPUT|TEXTAREA|SELECT/.test(document.activeElement?.tagName) || document.activeElement?.isContentEditable;
  const fragment = (markup, wrap = "") => { const t = document.createElement("template"); t.innerHTML = wrap ? `<${wrap}>${markup}</${wrap}>` : markup; return t.content; }; // server-escaped markup only
  async function post(url, data) {
    const r = await fetch(url, { method: "POST", body: new URLSearchParams(data), credentials: "same-origin" });
    const j = await r.json().catch(() => ({ error: `HTTP ${r.status}` }));
    if (!r.ok || j.error) throw new Error(j.error || `HTTP ${r.status}`);
    return j;
  }

  // ---- theme: system / light / dark (applied before first paint)
  const THEMES = [["", "◐", "Theme: follows the system"], ["light", "☀", "Theme: light"], ["dark", "☾", "Theme: dark"]];
  const applyTheme = (t) => { if (t) document.documentElement.dataset.theme = t; else delete document.documentElement.dataset.theme; };
  applyTheme(store.get("sbx-theme") || "");

  function toast(msg, link) {
    const box = $("#toasts");
    if (!box) return;
    const t = el("div", { className: "toast" }, msg);
    if (link) t.append(" ", el("a", { href: link.href, textContent: link.text }));
    box.append(t);
    setTimeout(() => t.classList.add("out"), link ? 6000 : 1800);
    setTimeout(() => t.remove(), link ? 6400 : 2200);
  }
  async function copy(text, what = "Copied") {
    try { await navigator.clipboard.writeText(text); toast(what); } catch (e) { toast("Copy failed (clipboard needs https or localhost)"); }
  }
  const widths = (root) => {
    for (const s of $$("[data-w]", root)) s.style.width = `${s.dataset.w}%`;
    for (const s of $$("[data-x]", root)) s.style.left = `${s.dataset.x}%`;
  };

  // Rough client-side mirror of the server's URL extraction, for the live count.
  function countUrls(text) {
    let urls = 0, other = 0;
    const seen = new Set();
    for (const t of text.split(/[\s,;|]+/).filter(Boolean)) {
      const s = t.replace(/^[<"'(\[]+|[>"')\];.]+$/g, "").replace(/^hxxp/i, "http").replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)/gi, ".").replace(/\[:\]/g, ":");
      if (!s) continue;
      const ok = /^https?:\/\/[^/\s]+\.[^/\s]+/i.test(s) || /^([a-z0-9-]+\.)+[a-z][a-z0-9-]+([/?#:]|$)/i.test(s) || /^\d{1,3}(\.\d{1,3}){3}([/?#:]|$)/.test(s);
      if (ok) { if (!seen.has(s.toLowerCase())) { seen.add(s.toLowerCase()); urls++; } } else other++;
    }
    return { urls, other };
  }

  // ---- customization panel: profiles, changed-value highlighting
  function setupOptions(form) {
    const summary = $("#options-summary");
    const body = () => $("#options-body");
    const isChanged = (f) => (f.type === "checkbox" ? (f.checked ? "1" : "0") : f.value) !== f.dataset.default;
    const refresh = () => {
      const b = body();
      if (!b) return;
      let n = 0;
      for (const f of $$("[data-default]", b)) {
        const c = isChanged(f);
        (f.closest("label") || f.closest("details"))?.classList.toggle("changed", c);
        if (c) n++;
      }
      const profile = $("#profile", b).value;
      const extra = $("textarea[name=extra]", b).value.trim();
      const persona = $("select[name=persona]", b).value;
      const parts = [profile && `profile ${profile}`, persona !== "desktop" && persona, n && `${n} change${n === 1 ? "" : "s"}`, extra && "extra settings"].filter(Boolean);
      summary.textContent = `(${b.dataset.source && !n ? b.dataset.source : parts.join(" · ") || "defaults"})`;
    };
    const load = async (profile) => {
      const r = await fetch(`/partials/options?profile=${encodeURIComponent(profile || "")}`, { credentials: "same-origin" });
      if (!r.ok) return;
      body().replaceWith(fragment(await r.text()).firstElementChild);
      store.set("sbx-profile", profile || "");
      refresh();
    };
    const postForm = (url, extra) => { const p = new URLSearchParams(new FormData(form)); for (const [k, v] of Object.entries(extra)) p.set(k, v); return post(url, p); };
    form.addEventListener("input", refresh);
    form.addEventListener("change", (e) => { if (e.target.id === "profile") load(e.target.value); else refresh(); });
    form.addEventListener("click", async (e) => {
      const id = e.target.id;
      if (id === "options-reset") { e.preventDefault(); load(""); }
      else if (id === "profile-save") {
        e.preventDefault();
        const name = $("#profile-name").value.trim();
        if (!name) { $("#profile-name").focus(); toast("Name the profile first"); return; }
        try { await postForm("/profiles", { profileName: name }); await load(name); toast(`Profile “${name}” saved`); } catch (err) { toast(err.message); }
      } else if (id === "profile-delete") {
        e.preventDefault();
        const name = $("#profile").value;
        if (!name || !confirm(`Delete profile “${name}”?`)) return;
        try { await postForm("/profiles/delete", { profileName: name }); await load(""); toast("Profile deleted"); } catch (err) { toast(err.message); }
      }
    });
    // Restore the last profile unless the page was opened for something specific.
    const last = store.get("sbx-profile");
    if (last && !body()?.dataset.source && !$("#profile").value && !new URLSearchParams(location.search).size && $(`#profile option[value="${CSS.escape(last)}"]`)) load(last);
    else refresh();
  }

  document.addEventListener("DOMContentLoaded", () => {
    // ---- theme toggle
    const themeBtn = $("#theme");
    const showTheme = () => { const t = THEMES.find(([k]) => k === (store.get("sbx-theme") || "")) || THEMES[0]; themeBtn.title = `${t[2]} (click to change)`; };
    if (themeBtn) {
      showTheme();
      themeBtn.addEventListener("click", () => {
        const i = THEMES.findIndex(([k]) => k === (store.get("sbx-theme") || ""));
        const next = THEMES[(i + 1) % THEMES.length][0];
        store.set("sbx-theme", next); applyTheme(next); showTheme();
      });
    }

    // ---- screenshot lightbox (Esc or click closes)
    const lb = $("#lightbox");
    const openLightbox = (src, caption) => { $("img", lb).src = src; $(".lb-caption", lb).textContent = caption || ""; lb.hidden = false; };
    document.addEventListener("keydown", (e) => { if (e.key === "Escape") for (const o of $$(".overlay")) o.hidden = true; });
    for (const o of $$(".overlay")) o.addEventListener("click", (e) => { if (e.target === o || e.target.closest("[data-close]") || e.target.closest(".lb-body img")) o.hidden = true; });

    // ---- tabs (hash-addressable: #indicators, #network, ...)
    const tabs = $$(".tabs [data-tab]");
    const showTab = () => {
      const want = location.hash.slice(1);
      const id = tabs.some((t) => t.dataset.tab === want) ? want : tabs[0].dataset.tab;
      for (const t of tabs) t.classList.toggle("on", t.dataset.tab === id);
      for (const p of $$(".panel")) p.classList.toggle("on", p.id === `tab-${id}`);
    };
    if (tabs.length) { window.addEventListener("hashchange", showTab); showTab(); }

    // ---- client-side filtering (indicators, network, console, batch rows)
    const filterTable = (table) => {
      if (!table) return;
      const scope = table.closest(".card, .panel") || document;
      const q = ($(`input.filter[data-filter="#${table.id}"]`)?.value || "").trim().toLowerCase();
      const types = $$(`[data-chips="#${table.id}"] .chip.on`).map((c) => c.dataset.type);
      const flag = $(".seg [data-show].on", scope)?.dataset.show || "";
      let shown = 0;
      for (const tr of table.tBodies[0].rows) {
        if (tr.classList.contains("detail")) { tr.hidden = tr.hidden || tr.previousElementSibling.hidden; continue; }
        const ok = (!q || tr.textContent.toLowerCase().includes(q)) && (!types.length || types.includes(tr.dataset.type)) && (!flag || (tr.dataset.flags || "").split(" ").includes(flag));
        tr.hidden = !ok;
        if (!ok && tr.nextElementSibling?.classList.contains("detail")) tr.nextElementSibling.hidden = true;
        if (ok) shown++;
      }
      const empty = $(".empty-filter", scope);
      if (empty) empty.hidden = shown > 0;
    };
    for (const input of $$("input.filter[data-filter]")) input.addEventListener("input", () => filterTable($(input.dataset.filter)));
    for (const group of $$("[data-chips]")) {
      group.addEventListener("click", (e) => {
        const chip = e.target.closest(".chip");
        if (!chip) return;
        chip.classList.toggle("on");
        filterTable($(group.dataset.chips));
      });
    }
    for (const seg of $$(".seg")) {
      seg.addEventListener("click", (e) => {
        const b = e.target.closest("button[data-show]");
        if (!b) return;
        for (const x of $$("button", seg)) x.classList.toggle("on", x === b);
        filterTable($("table", seg.closest(".card")));
      });
    }

    // ---- scan list: server-side search, show filters, paging, selection
    const list = $("#scans"), search = $("#scan-search");
    let listQ = search?.value || "", listShow = $("#scan-show .on")?.dataset.filterShow || "";
    const loadScans = async ({ append = false } = {}) => {
      const more = $("#scan-more");
      const offset = append ? Number(more.dataset.offset) : 0;
      const r = await fetch(`/partials/scans?q=${encodeURIComponent(listQ)}&show=${encodeURIComponent(listShow)}&offset=${offset}`, { credentials: "same-origin" });
      if (!r.ok) return;
      const j = await r.json();
      const fresh = fragment(j.html, "table").querySelector("tbody");
      if (append) $("#scan-rows").append(...fresh.children);
      else $("#scan-rows").replaceWith(fresh);
      $("#scan-total").textContent = j.total;
      $("#scan-empty").hidden = j.total > 0;
      more.hidden = j.next === null; more.dataset.offset = j.next ?? 0;
      const u = new URL(location.href);
      u.searchParams.delete("q"); u.searchParams.delete("show");
      if (listQ) u.searchParams.set("q", listQ);
      if (listShow) u.searchParams.set("show", listShow);
      history.replaceState(null, "", u);
      updateSelection();
    };
    if (list) {
      let t = null;
      search.addEventListener("input", () => { clearTimeout(t); t = setTimeout(() => { listQ = search.value.trim(); loadScans(); }, 220); });
      $("#scan-show").addEventListener("click", (e) => {
        const b = e.target.closest("[data-filter-show]");
        if (!b) return;
        for (const x of $$("#scan-show button")) x.classList.toggle("on", x === b);
        listShow = b.dataset.filterShow; loadScans();
      });
      $("#scan-more").addEventListener("click", () => loadScans({ append: true }));
    }
    const rows = () => $$("#scan-rows tr.scan-row");
    const picked = () => rows().filter((tr) => $(".pick", tr)?.checked);
    function updateSelection() {
      const bar = $("#selbar");
      if (!bar) return;
      const n = picked().length;
      for (const tr of rows()) tr.classList.toggle("picked", $(".pick", tr).checked);
      bar.hidden = !n;
      $("#sel-count").textContent = `${n} selected`;
      const all = $("#pick-all");
      if (all) { all.checked = n && n === rows().length; all.indeterminate = n > 0 && n < rows().length; }
    }
    document.addEventListener("change", (e) => {
      if (e.target.id === "pick-all") { for (const tr of rows()) $(".pick", tr).checked = e.target.checked; updateSelection(); }
      else if (e.target.classList.contains("pick")) updateSelection();
    });
    $("#selbar")?.addEventListener("click", async (e) => {
      const b = e.target.closest("[data-bulk]");
      if (!b) return;
      const sel = picked(), ids = sel.map((tr) => tr.dataset.id), act = b.dataset.bulk;
      if (act === "clear") { for (const tr of rows()) $(".pick", tr).checked = false; updateSelection(); return; }
      if (act === "export") { location.href = `/export/iocs.csv?ids=${ids.join(",")}`; return; }
      if (act === "rescan") {
        const ta = $("#urls");
        ta.value = sel.map((tr) => tr.dataset.url).join("\n");
        ta.dispatchEvent(new Event("input"));
        ta.scrollIntoView({ block: "center" }); ta.focus();
        toast(`${ids.length} URL${ids.length === 1 ? "" : "s"} ready. Check the options, then press Scan`);
        return;
      }
      if (act === "delete" && !confirm(`Delete ${ids.length} scan${ids.length === 1 ? "" : "s"} and all their files? This can't be undone.`)) return;
      try {
        const j = await post("/scans/bulk", { ids: ids.join(","), action: act });
        toast(act === "delete" ? `Deleted ${j.n} scan${j.n === 1 ? "" : "s"}` : `Marked ${j.n} as ${act.slice(8)}`);
        await loadScans();
      } catch (err) { toast(err.message); }
    });
    // ---- report: verdict, tags/notes autosave, copy summary
    const triageScan = $(".verdict-set")?.dataset.scan;
    // Clicking the active verdict clears it.
    const setVerdict = async (v) => {
      const on = $(`.verdict-set [data-verdict="${v}"]`)?.classList.contains("on");
      try {
        const t = await post(`/scans/${triageScan}/triage`, { verdict: on ? "" : v });
        for (const b of $$(".verdict-set button")) b.classList.toggle("on", b.dataset.verdict === t.verdict);
        $("#triage-state").textContent = "saved just now";
        toast(t.verdict ? `Marked ${t.verdict}` : "Verdict cleared");
      } catch (err) { toast(err.message); }
    };
    $(".verdict-set")?.addEventListener("click", (e) => { const b = e.target.closest("[data-verdict]"); if (b) setVerdict(b.dataset.verdict); });
    const tags = $("#triage-tags"), notes = $("#triage-notes");
    if (tags) {
      let t = null;
      const save = async () => {
        $("#triage-state").textContent = "saving…";
        try { await post(`/scans/${triageScan}/triage`, { tags: tags.value, notes: notes.value }); $("#triage-state").textContent = "saved just now"; } catch (err) { $("#triage-state").textContent = `not saved: ${err.message}`; }
      };
      for (const f of [tags, notes]) f.addEventListener("input", () => { $("#triage-state").textContent = "editing…"; clearTimeout(t); t = setTimeout(save, 700); });
      window.addEventListener("beforeunload", () => { if (t) { clearTimeout(t); navigator.sendBeacon?.(`/scans/${triageScan}/triage`, new URLSearchParams({ tags: tags.value, notes: notes.value })); } });
    }

    // ---- clicks (delegated, so swapped rows work)
    document.addEventListener("click", async (e) => {
      const lbt = e.target.closest("[data-lightbox]");
      if (lbt && !e.ctrlKey && !e.metaKey) { e.preventDefault(); openLightbox(lbt.dataset.lightbox, lbt.dataset.caption); return; }
      const btn = e.target.closest("button.copy");
      if (btn) { copy(btn.dataset.copy); return; }
      const cf = e.target.closest("button.copy-fetch");
      if (cf) {
        try { const r = await fetch(cf.dataset.src, { credentials: "same-origin" }); await copy(await r.text(), "Summary copied as Markdown"); } catch (err) { toast("Copy failed"); }
        return;
      }
      const cv = e.target.closest("button.copy-visible");
      if (cv) {
        const vis = $$(`${cv.dataset.table} tbody tr`).filter((tr) => !tr.hidden && tr.dataset.value);
        copy(vis.map((tr) => tr.dataset.value).join("\n"), `Copied ${vis.length} value${vis.length === 1 ? "" : "s"}`);
        return;
      }
      if (e.target.closest("a, button, input, select, summary, label, textarea")) return;
      if (window.getSelection().toString()) return;
      const tr = e.target.closest("tr");
      if (!tr) return;
      if (tr.dataset.href) { if (e.ctrlKey || e.metaKey) window.open(tr.dataset.href); else location.href = tr.dataset.href; }
      else if (tr.classList.contains("expander")) { const d = tr.nextElementSibling; d.hidden = !d.hidden; tr.classList.toggle("open", !d.hidden); }
    });
    document.addEventListener("click", (e) => { for (const m of $$("details.menu[open]")) if (!m.contains(e.target)) m.open = false; });

    // ---- screenshot switch
    for (const sw of $$(".shot-switch")) {
      sw.addEventListener("click", (e) => {
        const b = e.target.closest("button[data-shot]");
        if (!b) return;
        for (const x of $$("button", sw)) x.classList.toggle("on", x === b);
        for (const p of $$("[data-shot-panel]", sw.parentElement)) p.hidden = p.dataset.shotPanel !== b.dataset.shot;
      });
    }

    widths(document);

    // ---- submit form: autogrow, file load, paste/drop anywhere
    const form = $("#scan-form");
    if (form) {
      const ta = $("#urls", form);
      const grow = () => { ta.style.height = "auto"; ta.style.height = `${Math.min(ta.scrollHeight + 2, 320)}px`; };
      ta.addEventListener("input", grow);
      grow();
      form.addEventListener("submit", () => { const b = $("button[type=submit]", form); b.disabled = true; b.firstChild.textContent = "Queuing…"; });
      if (location.hash === "#new") ta.focus();
      setupOptions(form);
      const count = $("#url-count"), bname = $("#batch-name"), btn = $("button[type=submit]", form);
      const recount = () => {
        const { urls, other } = countUrls(ta.value);
        count.textContent = !urls ? (other ? "no URLs found yet" : "") : `${urls} URL${urls === 1 ? "" : "s"}${urls > 1 ? " → batch" : ""}${other ? ` · ${other} other token${other === 1 ? "" : "s"} will be skipped` : ""}${urls > 1000 ? " · max 1000 per batch" : ""}`;
        count.classList.toggle("error", urls > 1000);
        bname.hidden = urls < 2;
        btn.firstChild.textContent = urls > 1 ? `Scan ${urls}` : "Scan";
      };
      ta.addEventListener("input", recount);
      const loadFile = (file) => {
        if (!file) return;
        if (file.size > 2e6) { toast("File too large (max 2 MB)"); return; }
        const r = new FileReader();
        r.onload = () => {
          ta.value = (ta.value.trim() ? `${ta.value.trim()}\n` : "") + r.result;
          if (!bname.value) bname.value = file.name.replace(/\.[^.]+$/, "").slice(0, 80);
          grow(); recount(); ta.focus(); toast(`Loaded ${file.name}`);
        };
        r.readAsText(file);
      };
      $("#url-file").addEventListener("change", (e) => { loadFile(e.target.files[0]); e.target.value = ""; });
      // Drop a file or paste URLs anywhere on the dashboard.
      document.addEventListener("dragover", (e) => { if (e.dataTransfer.types.includes("Files")) { e.preventDefault(); ta.classList.add("drop"); } });
      document.addEventListener("dragleave", (e) => { if (!e.relatedTarget) ta.classList.remove("drop"); });
      document.addEventListener("drop", (e) => { if (e.dataTransfer.files.length) { e.preventDefault(); ta.classList.remove("drop"); loadFile(e.dataTransfer.files[0]); } });
      document.addEventListener("paste", (e) => {
        if (typing()) return;
        const text = e.clipboardData.getData("text");
        if (!countUrls(text).urls) return;
        e.preventDefault();
        ta.value = (ta.value.trim() ? `${ta.value.trim()}\n` : "") + text;
        ta.dispatchEvent(new Event("input"));
        ta.scrollIntoView({ block: "center" }); ta.focus();
        toast("Pasted into the scan box. Press Scan to start.");
      });
      recount();
    }
    for (const a of $$("[data-focus]")) {
      a.addEventListener("click", (e) => { const t = $(a.dataset.focus); if (t) { e.preventDefault(); t.scrollIntoView({ block: "center" }); t.focus(); } });
    }

    // ---- live queue (header pill everywhere, table on the dashboard)
    const pill = $("#queue-pill"), qCard = $("#queue"), qRows = $("#queue-rows");
    const states = new Map();
    let timer = null;
    const renderQueue = (q) => {
      const active = q.running + q.queued;
      if (pill) { pill.hidden = !active; $("#queue-pill-text").textContent = `${q.running} running${q.queued ? ` · ${q.queued} queued` : ""}`; }
      if (!qRows) return;
      const recent = q.jobs.filter((j) => j.state === "queued" || j.state === "running" || Date.now() - new Date(j.finishedAt) < 15 * 60e3).reverse();
      qCard.hidden = !recent.length && !q.batches.length;
      $("#queue-status").textContent = active ? `${q.running} running · ${q.queued} queued` : "idle";
      const batchRows = q.batches.map((b) => {
        const tr = el("tr", { className: "clickable" },
          el("td", {}, el("span", { className: "badge state running", textContent: "batch" })),
          el("td", { textContent: b.name }),
          el("td", { className: "muted", textContent: `${b.finished}/${b.total}` }),
          el("td", { className: "right" }, el("a", { href: `/batches/${b.id}`, textContent: "Open", className: "button small" })));
        tr.dataset.href = `/batches/${b.id}`;
        return tr;
      });
      qRows.replaceChildren(...batchRows, ...recent.map((j) => {
        const since = j.state === "running" ? j.startedAt : j.state === "queued" ? j.queuedAt : null;
        const action = j.scanId ? el("a", { href: `/scans/${j.scanId}`, textContent: "Open report", className: "button small" })
          : j.error ? el("span", { className: "error", textContent: j.error }) : el("span", { className: "muted elapsed", textContent: since ? secs(Date.now() - new Date(since)) : "" });
        if (since) action.dataset.since = since;
        const tr = el("tr", {},
          el("td", {}, el("span", { className: `badge state ${j.state}`, textContent: j.state })),
          el("td", { className: "mono url", textContent: defang(j.url), title: defang(j.url) }),
          el("td", { className: "muted", textContent: j.persona }),
          el("td", { className: "right" }, action));
        if (j.scanId) { tr.dataset.href = `/scans/${j.scanId}`; tr.className = "clickable"; }
        return tr;
      }));
    };
    const poll = async () => {
      let q = null;
      try { const r = await fetch("/api/queue", { credentials: "same-origin" }); if (r.ok) q = await r.json(); } catch (e) { /* offline */ }
      if (q) {
        let finished = false;
        for (const j of q.jobs) {
          const prev = states.get(j.id);
          if (prev && prev !== j.state && (j.state === "done" || j.state === "failed") && !j.batchId) {
            finished = true;
            if (!$(`[data-job="${j.id}"]`)) {
              if (j.state === "done") toast(`Scan finished: ${defang(new URL(j.url).hostname)}`, { href: `/scans/${j.scanId}`, text: "Open" });
              else toast(`Scan failed: ${defang(new URL(j.url).hostname)}`);
            }
          }
          states.set(j.id, j.state);
        }
        renderQueue(q);
        if (finished && list && !picked().length) loadScans().catch(() => {});
      }
      const active = q && q.running + q.queued;
      timer = setTimeout(poll, document.hidden ? 15000 : active ? 2000 : 8000);
    };
    poll();
    document.addEventListener("visibilitychange", () => { if (!document.hidden) { clearTimeout(timer); poll(); } });
    setInterval(() => { for (const e of $$("[data-since]")) if (e.classList.contains("elapsed") || e.id === "job-elapsed") e.textContent = e.id === "job-elapsed" ? `Elapsed ${secs(Date.now() - new Date(e.dataset.since))}.` : secs(Date.now() - new Date(e.dataset.since)); }, 1000);
    setInterval(() => { for (const e of $$("[data-at]")) e.textContent = ago(e.dataset.at); }, 30000);

    // ---- batch page: live progress
    const batch = $("#batch");
    if (batch && batch.dataset.active) {
      const tick = async () => {
        let b = null;
        try { const r = await fetch(`/api/batches/${batch.dataset.batch}`, { credentials: "same-origin" }); if (r.ok) b = await r.json(); } catch (e) { /* retry */ }
        if (b) {
          const stats = $("#batch-stats");
          stats.replaceChildren(fragment(b.stats));
          widths(stats);
          $("#batch-rows").replaceWith(fragment(b.rows, "table").querySelector("tbody"));
          filterTable($("#batch-table"));
          $("#cancel-form").hidden = !b.queued || b.cli;
          $("#retry-form").hidden = b.active || !(b.failed + b.cancelled);
          if (!b.active) { toast(`Batch finished: ${b.done} done${b.failed ? `, ${b.failed} failed` : ""}`); return; }
        }
        setTimeout(tick, document.hidden ? 10000 : 2500);
      };
      setTimeout(tick, 2500);
    }

    // ---- job page: follow one job, open its report when done
    const job = $("[data-job].job");
    if (job) {
      const stateEl = $("#job-state"), steps = $$("#job-steps li"), spin = $(".spinner", job);
      const order = ["queued", "running", "done"];
      const mark = (s) => steps.forEach((li) => { const i = order.indexOf(li.dataset.step), k = order.indexOf(s); li.className = i < k ? "past" : i === k ? "now" : ""; });
      const follow = async () => {
        let j = null;
        try { const r = await fetch(`/api/jobs/${job.dataset.job}`, { credentials: "same-origin" }); if (r.ok) j = await r.json(); } catch (e) { /* retry */ }
        if (j?.state === "done") { mark("done"); stateEl.textContent = "Done, opening the report…"; location.replace(`/scans/${j.scanId}`); return; }
        if (j?.state === "failed") { spin.classList.add("stopped"); stateEl.replaceChildren(el("span", { className: "error", textContent: `Failed: ${j.error}` })); return; }
        if (j) {
          mark(j.state);
          stateEl.textContent = j.state === "running" ? "Scanning…" : "Queued";
          const since = $("#job-elapsed");
          if (j.startedAt && since) since.dataset.since = j.startedAt;
        }
        setTimeout(follow, 1500);
      };
      follow();
    }
  });
})();
