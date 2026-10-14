/* Harbor website: menu toggle, product screen tabs, and the depth contours drawn
   behind the navy bands (a static chart, redrawn only when the size changes). */
(function () {
  "use strict";

  /* ---------- menu on small screens ---------- */
  var nav = document.querySelector(".nav");
  var toggle = document.querySelector(".nav-toggle");
  if (nav && toggle) {
    toggle.addEventListener("click", function () {
      var open = nav.classList.toggle("open");
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
      toggle.textContent = open ? "Close" : "Menu";
    });
    nav.addEventListener("click", function (e) {
      if (e.target.closest("a") && nav.classList.contains("open")) toggle.click();
    });
  }

  /* ---------- product screen tabs ---------- */
  document.querySelectorAll("[data-tabs]").forEach(function (root) {
    var tabs = Array.prototype.slice.call(root.querySelectorAll('[role="tab"]'));
    function select(tab, focus) {
      tabs.forEach(function (t) {
        var on = t === tab;
        t.setAttribute("aria-selected", on ? "true" : "false");
        t.tabIndex = on ? 0 : -1;
        var panel = document.getElementById(t.getAttribute("aria-controls"));
        if (panel) panel.hidden = !on;
      });
      if (focus) tab.focus();
      if (window.matchMedia("(max-width: 920px)").matches) {
        tab.scrollIntoView({ block: "nearest", inline: "center", behavior: "smooth" });
      }
    }
    tabs.forEach(function (tab, i) {
      tab.addEventListener("click", function () { select(tab, false); });
      tab.addEventListener("keydown", function (e) {
        var next = null;
        if (e.key === "ArrowDown" || e.key === "ArrowRight") next = tabs[(i + 1) % tabs.length];
        if (e.key === "ArrowUp" || e.key === "ArrowLeft") next = tabs[(i - 1 + tabs.length) % tabs.length];
        if (e.key === "Home") next = tabs[0];
        if (e.key === "End") next = tabs[tabs.length - 1];
        if (next) { e.preventDefault(); select(next, true); }
      });
    });
  });

  /* ---------- depth contours ---------- */
  function rng(seed) {
    return function () {
      seed = (seed * 1664525 + 1013904223) >>> 0;
      return seed / 4294967296;
    };
  }

  function field(w, h, seed) {
    // a sea floor: a few broad basins and shoals plus gentle ripples
    var r = rng(seed), blobs = [];
    for (var i = 0; i < 9; i++) {
      blobs.push({ x: r() * w, y: r() * h, s: (0.18 + r() * 0.35) * Math.max(w, h), a: (r() - 0.45) * 2 });
    }
    var ph = [r() * 6.28, r() * 6.28, r() * 6.28];
    return function (x, y) {
      var v = 0;
      for (var k = 0; k < blobs.length; k++) {
        var b = blobs[k], dx = x - b.x, dy = y - b.y;
        v += b.a * Math.exp(-(dx * dx + dy * dy) / (2 * b.s * b.s));
      }
      v += 0.08 * Math.sin(x / 140 + ph[0]) * Math.cos(y / 170 + ph[1]);
      v += 0.04 * Math.sin((x + y) / 90 + ph[2]);
      return v;
    };
  }

  function draw(canvas) {
    var rect = canvas.getBoundingClientRect();
    var w = Math.max(1, Math.round(rect.width)), h = Math.max(1, Math.round(rect.height));
    var dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = w * dpr; canvas.height = h * dpr;
    var ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    var f = field(w, h, Number(canvas.dataset.seed || 3));
    var cell = 9, cols = Math.ceil(w / cell) + 1, rows = Math.ceil(h / cell) + 1;
    var grid = new Float32Array(cols * rows), min = Infinity, max = -Infinity;
    for (var j = 0; j < rows; j++) for (var i = 0; i < cols; i++) {
      var v = f(i * cell, j * cell);
      grid[j * cols + i] = v;
      if (v < min) min = v;
      if (v > max) max = v;
    }
    var levels = 15;
    for (var l = 1; l < levels; l++) {
      var t = min + (max - min) * (l / levels);
      var major = l % 5 === 0;
      ctx.strokeStyle = major ? "rgba(95, 211, 192, 0.22)" : "rgba(157, 180, 189, 0.11)";
      ctx.lineWidth = major ? 1.1 : 0.8;
      ctx.beginPath();
      for (var y = 0; y < rows - 1; y++) for (var x = 0; x < cols - 1; x++) {
        var a = grid[y * cols + x], b = grid[y * cols + x + 1], c = grid[(y + 1) * cols + x + 1], d = grid[(y + 1) * cols + x];
        var idx = (a > t ? 8 : 0) | (b > t ? 4 : 0) | (c > t ? 2 : 0) | (d > t ? 1 : 0);
        if (idx === 0 || idx === 15) continue;
        var px = x * cell, py = y * cell;
        var top = [px + cell * (t - a) / (b - a), py], right = [px + cell, py + cell * (t - b) / (c - b)];
        var bottom = [px + cell * (t - d) / (c - d), py + cell], left = [px, py + cell * (t - a) / (d - a)];
        var segs = {
          1: [[left, bottom]], 2: [[bottom, right]], 3: [[left, right]], 4: [[top, right]], 5: [[left, top], [bottom, right]],
          6: [[top, bottom]], 7: [[left, top]], 8: [[left, top]], 9: [[top, bottom]], 10: [[top, right], [left, bottom]],
          11: [[top, right]], 12: [[left, right]], 13: [[bottom, right]], 14: [[left, bottom]]
        }[idx];
        for (var s = 0; s < segs.length; s++) {
          ctx.moveTo(segs[s][0][0], segs[s][0][1]);
          ctx.lineTo(segs[s][1][0], segs[s][1][1]);
        }
      }
      ctx.stroke();
    }
  }

  var canvases = Array.prototype.slice.call(document.querySelectorAll("[data-contours]"));
  if (canvases.length && "getContext" in document.createElement("canvas")) {
    var sizes = new WeakMap();
    var redraw = function () {
      canvases.forEach(function (c) {
        var r = c.getBoundingClientRect(), key = Math.round(r.width) + "x" + Math.round(r.height);
        if (sizes.get(c) !== key) { sizes.set(c, key); draw(c); }
      });
    };
    var timer = null;
    window.addEventListener("resize", function () { clearTimeout(timer); timer = setTimeout(redraw, 150); });
    redraw();
  }
})();
