// Small progressive enhancements. Every feature also works without JS
// except prompts for names (rename / new file / new folder).
document.addEventListener("DOMContentLoaded", () => {
  // Confirm destructive actions
  document.querySelectorAll("form[data-confirm]").forEach((f) =>
    f.addEventListener("submit", (e) => { if (!confirm(f.dataset.confirm)) e.preventDefault(); }));

  // Ask for a name, then submit
  document.querySelectorAll("form[data-prompt]").forEach((f) =>
    f.addEventListener("submit", (e) => {
      const v = prompt(f.dataset.promptText || "Name", f.dataset.promptDefault || "");
      if (!v) { e.preventDefault(); return; }
      f.querySelector(`input[name="${f.dataset.prompt}"]`).value = v.trim();
    }));

  // Busy state for slow actions
  document.querySelectorAll("form").forEach((f) =>
    f.addEventListener("submit", (e) => {
      if (e.defaultPrevented) return;
      const b = f.querySelector("button:not(.linkish)");
      if (b && f.dataset.busy) { b.disabled = true; b.textContent = f.dataset.busy; }
    }));

  // Copy buttons for one-time secrets
  document.querySelectorAll("[data-copy]").forEach((b) =>
    b.addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(b.dataset.copy); b.textContent = "Copied"; }
      catch { b.textContent = "Select & copy"; }
    }));

  // Upload: submit when files are picked, and support drag & drop
  document.querySelectorAll("input[data-autosubmit]").forEach((i) =>
    i.addEventListener("change", () => i.files.length && i.form.submit()));
  const drop = document.querySelector("[data-drop]");
  const upInput = document.querySelector("input[data-autosubmit]");
  if (drop && upInput) {
    ["dragenter", "dragover"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.add("over"); }));
    ["dragleave", "drop"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
    drop.addEventListener("drop", (e) => {
      if (!e.dataTransfer.files.length) return;
      upInput.files = e.dataTransfer.files;
      upInput.form.submit();
    });
  }

  // Editor: Tab inserts spaces, Ctrl/Cmd+S saves, warn on unsaved changes
  const ed = document.querySelector("form[data-editor]");
  if (ed) {
    const ta = ed.querySelector("textarea"), dirty = ed.querySelector("[data-dirty]");
    let changed = false;
    ta.addEventListener("input", () => { changed = true; dirty.hidden = false; });
    ta.addEventListener("keydown", (e) => {
      if (e.key === "Tab" && !e.shiftKey) {
        e.preventDefault();
        const s = ta.selectionStart;
        ta.setRangeText("    ", s, ta.selectionEnd, "end");
        changed = true; dirty.hidden = false;
      }
    });
    document.addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "s") { e.preventDefault(); changed = false; ed.submit(); }
    });
    ed.addEventListener("submit", () => { changed = false; });
    window.addEventListener("beforeunload", (e) => { if (changed) e.preventDefault(); });
  }

  // Logs: start at the newest line
  const log = document.querySelector("[data-scroll-bottom]");
  if (log) log.scrollTop = log.scrollHeight;

  // Backups page: refresh while a backup runs
  const ar = document.querySelector("[data-autorefresh]");
  if (ar) setTimeout(() => location.reload(), Number(ar.dataset.autorefresh) * 1000);

  // Dashboard: live stats
  const live = document.getElementById("live-stats");
  if (live) {
    const fmt = (n) => { const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0; while (n >= 1024 && i < 4) { n /= 1024; i++; } return (i ? n.toFixed(1) : n.toFixed(0)) + " " + u[i]; };
    const set = (k, v) => { const el = live.querySelector(`[data-stat="${k}"]`); if (el) el.textContent = v; };
    const bar = (k, v) => { const el = live.querySelector(`[data-bar="${k}"]`); if (el) el.value = v; };
    setInterval(async () => {
      try {
        const r = await fetch("/api/stats", { credentials: "same-origin" });
        if (!r.ok) return;
        const s = await r.json();
        set("cpu", Math.round(s.cpu) + "%"); bar("cpu", s.cpu);
        set("load", `Load ${s.load.map((x) => x.toFixed(2)).join(" · ")}`);
        set("mem", Math.round(s.mem_pct) + "%"); bar("mem", s.mem_pct);
        set("memsub", `${fmt(s.mem_used)} of ${fmt(s.mem_total)}`);
        set("disk", Math.round(s.disk_pct) + "%"); bar("disk", s.disk_pct);
        set("disksub", `${fmt(s.disk_used)} of ${fmt(s.disk_total)}`);
      } catch {}
    }, 5000);
  }
});

// Users page: show site checkboxes only for team users
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("select[data-role-select]").forEach((sel) => {
    const box = sel.form.querySelector("[data-site-checks]");
    if (!box) return;
    const sync = () => box.classList.toggle("is-hidden", sel.value === "admin");
    sel.addEventListener("change", sync);
    sync();
  });
});

// Updates page: wait out the panel restart, then reload when the update finishes
document.addEventListener("DOMContentLoaded", () => {
  if (!document.querySelector("[data-update-poll]")) return;
  setInterval(async () => {
    try {
      const r = await fetch("/settings/updates/status", { credentials: "same-origin" });
      if (!r.ok) return;
      const s = await r.json();
      const logEl = document.querySelector("details.update pre.log");
      if (logEl && s.log) { logEl.textContent = s.log; logEl.scrollTop = logEl.scrollHeight; }
      if (!["queued", "running"].includes(s.status)) location.reload();
    } catch { /* panel is restarting */ }
  }, 4000);
});

// cPanel import: streamed upload with progress, and live progress while reading/importing
document.addEventListener("DOMContentLoaded", () => {
  const zone = document.querySelector("[data-upload-zone]");
  if (zone) {
    const input = zone.querySelector("[data-upload-input]");
    const bar = zone.querySelector("[data-upload-progress]");
    const label = zone.querySelector("[data-upload-label]");
    const csrf = zone.querySelector("[data-upload-csrf]").value;
    const fmt = (n) => (n / 1048576).toFixed(n > 1e9 ? 0 : 1) + " MB";
    const send = (file) => {
      if (!/\.(tar\.gz|tgz|tar)$/i.test(file.name)) { alert("Choose a cPanel backup (.tar.gz)"); return; }
      const xhr = new XMLHttpRequest();
      xhr.open("PUT", "/import/upload?name=" + encodeURIComponent(file.name));
      xhr.setRequestHeader("X-CSRF-Token", csrf);
      xhr.setRequestHeader("Content-Type", "application/octet-stream");
      bar.hidden = false;
      xhr.upload.onprogress = (e) => {
        if (!e.lengthComputable) return;
        bar.querySelector("progress").value = (e.loaded / e.total) * 100;
        label.textContent = `${fmt(e.loaded)} of ${fmt(e.total)}`;
      };
      xhr.onload = () => {
        try {
          const r = JSON.parse(xhr.responseText);
          if (xhr.status === 200) { location.href = r.url; return; }
          label.textContent = r.error || "Upload failed";
        } catch { label.textContent = "Upload failed (" + xhr.status + ")"; }
      };
      xhr.onerror = () => { label.textContent = "Upload failed: connection lost"; };
      xhr.send(file);
    };
    zone.querySelector("[data-upload-pick]").addEventListener("click", () => input.click());
    input.addEventListener("change", () => input.files[0] && send(input.files[0]));
    ["dragenter", "dragover"].forEach((t) => zone.addEventListener(t, (e) => { e.preventDefault(); zone.classList.add("over"); }));
    ["dragleave", "drop"].forEach((t) => zone.addEventListener(t, (e) => { e.preventDefault(); zone.classList.remove("over"); }));
    zone.addEventListener("drop", (e) => e.dataTransfer.files[0] && send(e.dataTransfer.files[0]));
  }
  const dpoll = document.querySelector("[data-deploy-poll]");
  if (dpoll) {
    const logEl = document.querySelector("[data-deploy-log]");
    const tick = setInterval(async () => {
      try {
        const r = await fetch(dpoll.dataset.deployPoll, { credentials: "same-origin" });
        const s = await r.json();
        if (logEl && s.log) { logEl.textContent = s.log; logEl.scrollTop = logEl.scrollHeight; }
        if (!["queued", "running"].includes(s.status)) { clearInterval(tick); location.reload(); }
      } catch {}
    }, 2000);
  }
  const poll = document.querySelector("[data-import-poll]");
  if (poll) {
    const id = poll.dataset.importPoll, logEl = document.querySelector("[data-import-log]");
    setInterval(async () => {
      try {
        const r = await fetch(`/import/${id}/status`, { credentials: "same-origin" });
        const s = await r.json();
        if (logEl) { logEl.textContent = s.log; logEl.scrollTop = logEl.scrollHeight; }
        if (!["downloading", "scanning", "importing"].includes(s.status)) location.reload();
      } catch {}
    }, 2500);
  }
});
