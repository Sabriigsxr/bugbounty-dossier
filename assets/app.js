/* ============================================================
   THE MINE — render + interaction
   No network calls. No dependencies. Data lives in data.js.
   ============================================================ */
(function () {
  "use strict";

  var DATA = window.MINE;
  if (!DATA) return;

  var $ = function (sel, root) { return (root || document).querySelector(sel); };
  var $$ = function (sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); };

  var reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function esc(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  var SEV_FILL = { critical: 100, high: 82, medium: 62, low: 42, info: 24 };
  var SEV_LABEL = { critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", low: "LOW", info: "INFO" };

  /* ---------------- core sample ---------------- */

  function renderCore() {
    var strip = $("#coreStrip");
    var labels = $("#coreLabels");
    var readout = $("#coreReadout");
    if (!strip) return;

    var html = "";
    var labelHtml = "";
    var all = [];

    DATA.shafts.forEach(function (shaft) {
      var veins = shaft.veins;
      if (!veins.length) return;
      all = all.concat(veins);
      html += '<div class="core__group" style="flex:' + veins.length + ' 1 0">';
      veins.forEach(function (v) {
        html +=
          '<button class="seam" type="button" data-seam="' + esc(v.id) + '"' +
          ' style="--sev:var(--sev-' + esc(v.severity) + ');--h:' + (SEV_FILL[v.severity] || 30) + '%"' +
          ' aria-label="' + esc(v.id + " — " + v.title + " — " + SEV_LABEL[v.severity]) + '"></button>';
      });
      html += "</div>";
      labelHtml +=
        '<div class="core__label" style="flex:' + veins.length + ' 1 0" title="' + esc(shaft.name) + '">' +
        "<b>" + esc(shaft.numeral) + "</b> · " + esc(shaft.name) + "</div>";
    });

    /* sealed band */
    var sealedCount = DATA.sealed.reduce(function (n, s) { return n + s.items; }, 0);
    if (sealedCount) {
      html += '<div class="core__group" style="flex:0 0 auto">';
      for (var i = 0; i < sealedCount; i++) {
        html += '<span class="seam" data-sealed aria-hidden="true"></span>';
      }
      html += "</div>";
      labelHtml += '<div class="core__label" style="flex:0 0 auto;padding-left:6px">SEALED · ' + sealedCount + "</div>";
    }

    strip.innerHTML = html;
    labels.innerHTML = labelHtml;

    var defaultText = readout.innerHTML;

    function show(v) {
      readout.innerHTML =
        "<b>" + esc(v.id) + "</b>" +
        '<span class="r-sev" style="color:var(--sev-' + esc(v.severity) + ')">' + esc(SEV_LABEL[v.severity]) + "</span>" +
        esc(v.title);
    }

    var byId = {};
    all.forEach(function (v) { byId[v.id] = v; });

    strip.addEventListener("mouseover", function (e) {
      var b = e.target.closest(".seam[data-seam]");
      if (!b) return;
      var v = byId[b.getAttribute("data-seam")];
      if (v) show(v);
    });

    strip.addEventListener("mouseleave", function () { readout.innerHTML = defaultText; });

    strip.addEventListener("focusin", function (e) {
      var b = e.target.closest(".seam[data-seam]");
      if (!b) return;
      var v = byId[b.getAttribute("data-seam")];
      if (v) show(v);
    });

    strip.addEventListener("click", function (e) {
      var b = e.target.closest(".seam[data-seam]");
      if (!b) return;
      jumpTo(b.getAttribute("data-seam"));
    });
  }

  /* ---------------- veins ---------------- */

  function triadHtml(triad) {
    if (!triad) return "";
    var rows = [
      ["CONFIDENTIALITY", triad.c],
      ["INTEGRITY", triad.i],
      ["AVAILABILITY", triad.a]
    ];
    return (
      '<div class="triad" aria-label="Impact triad, qualitative">' +
      rows.map(function (r) {
        var pips = "";
        for (var i = 1; i <= 3; i++) pips += '<span class="triad__pip"' + (i <= r[1] ? " data-on" : "") + "></span>";
        return '<span class="triad__item"><span>' + r[0] + '</span><span class="triad__pips">' + pips + "</span></span>";
      }).join("") +
      "</div>"
    );
  }

  function veinHtml(v) {
    var bodyId = "body-" + v.id;
    var score = v.score && v.score !== "—"
      ? '<b>' + esc(v.score) + "</b><i>" + esc(v.scale || "") + "</i>"
      : '<b style="color:var(--faint)">—</b><i>' + esc(v.scale || "unscored") + "</i>";

    return (
      '<article class="vein" id="' + esc(v.id) + '" data-vein="' + esc(v.id) + '" data-severity="' + esc(v.severity) + '" data-shaft="' + esc(v.shaftId) + '" data-search="' +
      esc([v.id, v.title, v.klass, v.cve || "", v.detail, v.impact].join(" ").toLowerCase()) + '">' +
        '<h3 class="vein__h">' +
          '<button class="vein__head" type="button" aria-expanded="false" aria-controls="' + bodyId + '">' +
            '<span class="vein__top">' +
              '<span class="vein__id">' + esc(v.id) + "</span>" +
              '<span class="vein__grade">' + esc(SEV_LABEL[v.severity]) + " · " + esc(v.grade) + "</span>" +
            "</span>" +
            '<span class="vein__title">' + esc(v.title) + "</span>" +
            '<span class="vein__tags">' + esc(v.klass) + (v.cve ? " · " + esc(v.cve) : "") + "</span>" +
            '<span class="vein__score">' + score + "</span>" +
            '<span class="vein__chev" aria-hidden="true"></span>' +
          "</button>" +
        "</h3>" +
        '<div class="vein__body" id="' + bodyId + '" hidden>' +
          '<div class="assay">' +
            '<div class="assay__col"><h4>Detail</h4><p>' + esc(v.detail) + "</p></div>" +
            '<div class="assay__col"><h4>Impact</h4><p>' + esc(v.impact) + "</p></div>" +
            '<div class="assay__col"><h4>Evidence</h4><p>' + esc(v.evidence) + "</p></div>" +
          "</div>" +
          triadHtml(v.triad) +
          '<div class="dig">' +
            '<div class="dig__head"><span>Next dig</span><span class="dig__label">' + esc(v.next.label) + "</span></div>" +
            '<div class="dig__code">' +
              "<pre><code>" + esc(v.next.cmd) + "</code></pre>" +
              '<button class="copy" type="button" data-copy="' + esc(v.next.cmd) + '">Copy</button>' +
            "</div>" +
            '<p class="dig__note">' + esc(v.next.note) + "</p>" +
          "</div>" +
        "</div>" +
      "</article>"
    );
  }

  function renderShafts() {
    var host = $("#seams");
    var html = "";

    DATA.shafts.forEach(function (shaft) {
      var cards = shaft.veins.map(function (v) {
        v.shaftId = shaft.id;
        return veinHtml(v);
      }).join("");

      html +=
        '<section class="shaft" id="shaft-' + esc(shaft.id) + '" data-shaft="' + esc(shaft.id) + '">' +
          '<div class="wrap">' +
            '<div class="shaft__head">' +
              '<div class="shaft__num" aria-hidden="true" title="Expand every seam in this shaft">' + esc(shaft.numeral) + "</div>" +
              "<div>" +
                '<h2 class="shaft__name">' + esc(shaft.name) + "</h2>" +
                '<p class="shaft__scope">' + esc(shaft.scope) + "</p>" +
              "</div>" +
              '<div class="shaft__right">' +
                '<span class="stamp stamp--' + esc(shaft.statusTone) + '">' + esc(shaft.status) + "</span>" +
                '<span class="shaft__sunk">' + esc(shaft.sunk) + "</span>" +
              "</div>" +
            "</div>" +
            '<p class="shaft__note">' + esc(shaft.note) + "</p>" +
            '<div class="veins">' + cards + "</div>" +
          "</div>" +
        "</section>";
    });

    host.innerHTML = html;
  }

  /* ---------------- tailings + sealed + method ---------------- */

  function renderTailings() {
    var tbody = $("#tailingsBody");
    if (!tbody) return;
    tbody.innerHTML = DATA.tailings.map(function (t) {
      return (
        "<tr>" +
          "<td>" + esc(t.asset) + "</td>" +
          '<td><span class="reason">' + esc(t.reason) + "</span></td>" +
          "<td>" + esc(t.note) + "</td>" +
        "</tr>"
      );
    }).join("");
  }

  function renderSealed() {
    var host = $("#sealedGrid");
    if (!host) return;
    var lock =
      '<svg class="seal__lock" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4" aria-hidden="true">' +
      '<rect x="4" y="10" width="16" height="11"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/><path d="M12 14v3"/></svg>';

    host.innerHTML = DATA.sealed.map(function (s, i) {
      return (
        '<article class="seal">' +
          '<div class="seal__top">' +
            "<div>" +
              '<span class="seal__num">' + String(i + 1).padStart(2, "0") + "</span>" +
              '<h3 class="seal__prog">' + esc(s.program) + "</h3>" +
              '<div class="seal__meta"><span>' + esc(s.klass) + '</span><span class="sev">' + esc(s.severity.toUpperCase()) + " × " + s.items + "</span></div>" +
            "</div>" +
            lock +
          "</div>" +
          '<p class="seal__note">' + esc(s.note) + "</p>" +
          '<span class="seal__status">' + esc(s.status) + "</span>" +
        "</article>"
      );
    }).join("");
  }

  function renderMethod() {
    var host = $("#gates");
    if (!host) return;
    host.innerHTML = DATA.method.map(function (g) {
      return (
        '<article class="gate">' +
          '<span class="gate__n">' + esc(g.n) + "</span>" +
          "<h3>" + esc(g.title) + "</h3>" +
          "<p>" + esc(g.body) + "</p>" +
        "</article>"
      );
    }).join("");
  }

  function renderGithub() {
    var tabs = $("#tabs");
    var panel = $("#panel");
    if (!tabs || !panel) return;

    tabs.innerHTML = DATA.github.tabs.map(function (t, i) {
      return (
        '<button class="tab" type="button" role="tab" id="tab-' + esc(t.id) + '"' +
        ' aria-controls="panel-' + esc(t.id) + '" aria-selected="' + (i === 0 ? "true" : "false") + '"' +
        ' tabindex="' + (i === 0 ? "0" : "-1") + '">' + esc(t.label) + "</button>"
      );
    }).join("");

    function paint(tab) {
      $$(".tab", tabs).forEach(function (b) {
        var on = b === tab;
        b.setAttribute("aria-selected", on ? "true" : "false");
        b.tabIndex = on ? 0 : -1;
      });
      var data = DATA.github.tabs.filter(function (t) { return t.id === tab.id.replace("tab-", ""); })[0];
      if (!data) return;
      panel.setAttribute("aria-labelledby", tab.id);
      panel.innerHTML =
        '<p class="panel__blurb">' + esc(data.blurb) + "</p>" +
        data.lines.map(function (l) {
          return (
            '<div class="cmd">' +
              '<div class="cmd__line"><span class="cmd__prompt" aria-hidden="true">$</span>' +
                "<code>" + esc(l.cmd) + "</code></div>" +
              '<p class="cmd__note">' + esc(l.note) + "</p>" +
              '<button class="copy" type="button" data-copy="' + esc(l.cmd) + '">Copy</button>' +
            "</div>"
          );
        }).join("");
    }

    paint($(".tab", tabs));

    tabs.addEventListener("click", function (e) {
      var b = e.target.closest(".tab");
      if (b) paint(b);
    });

    tabs.addEventListener("keydown", function (e) {
      var list = $$(".tab", tabs);
      var idx = list.indexOf(document.activeElement);
      if (idx < 0) return;
      var next = null;
      if (e.key === "ArrowRight") next = list[(idx + 1) % list.length];
      if (e.key === "ArrowLeft") next = list[(idx - 1 + list.length) % list.length];
      if (e.key === "Home") next = list[0];
      if (e.key === "End") next = list[list.length - 1];
      if (!next) return;
      e.preventDefault();
      next.focus();
      paint(next);
    });
  }

  /* ---------------- filters ---------------- */

  var state = { shaft: "all", severity: "all", q: "" };

  function applyFilters() {
    var shown = 0;

    $$(".vein").forEach(function (card) {
      var okShaft = state.shaft === "all" || card.getAttribute("data-shaft") === state.shaft;
      var okSev = state.severity === "all" || card.getAttribute("data-severity") === state.severity;
      var okQ = !state.q || card.getAttribute("data-search").indexOf(state.q) !== -1;
      var ok = okShaft && okSev && okQ;
      card.hidden = !ok;
      if (ok) shown++;
    });

    $$(".shaft").forEach(function (sec) {
      var any = $$(".vein", sec).some(function (c) { return !c.hidden; });
      sec.hidden = !any;
    });

    var empty = $("#empty");
    if (empty) empty.setAttribute("data-on", shown === 0 ? "1" : "0");

    /* the seam log mirrors the filter: worked-out seams fade, they do not vanish */
    $$(".seam[data-seam]").forEach(function (s) {
      var card = document.getElementById(s.getAttribute("data-seam"));
      if (card) s.setAttribute("data-dim", card.hidden ? "1" : "0");
    });

    var out = $("#count");
    if (out) out.innerHTML = "<b>" + shown + "</b> / " + $$(".vein").length + " seams";
  }

  function bindFilters() {
    $$("[data-filter-shaft]").forEach(function (b) {
      b.addEventListener("click", function () {
        state.shaft = b.getAttribute("data-filter-shaft");
        $$("[data-filter-shaft]").forEach(function (x) { x.setAttribute("aria-pressed", x === b ? "true" : "false"); });
        applyFilters();
      });
    });

    $$("[data-filter-sev]").forEach(function (b) {
      b.addEventListener("click", function () {
        state.severity = b.getAttribute("data-filter-sev");
        $$("[data-filter-sev]").forEach(function (x) { x.setAttribute("aria-pressed", x === b ? "true" : "false"); });
        applyFilters();
      });
    });

    var input = $("#q");
    if (input) {
      input.addEventListener("input", function () {
        state.q = input.value.trim().toLowerCase();
        applyFilters();
      });
    }
  }

  /* ---------------- expansion + copy + jump ---------------- */

  function setOpen(card, open) {
    var btn = $(".vein__head", card);
    var body = $(".vein__body", card);
    if (!btn || !body) return;
    btn.setAttribute("aria-expanded", open ? "true" : "false");
    body.hidden = !open;
    if (open) card.setAttribute("data-open", "1");
    else card.removeAttribute("data-open");
  }

  function jumpTo(id) {
    var card = document.getElementById(id);
    if (!card) return;
    /* clear filters if the card is hidden by them */
    if (card.hidden) {
      state.shaft = "all";
      state.severity = "all";
      state.q = "";
      var q = $("#q");
      if (q) q.value = "";
      $$("[data-filter-shaft]").forEach(function (x) { x.setAttribute("aria-pressed", x.getAttribute("data-filter-shaft") === "all" ? "true" : "false"); });
      $$("[data-filter-sev]").forEach(function (x) { x.setAttribute("aria-pressed", x.getAttribute("data-filter-sev") === "all" ? "true" : "false"); });
      applyFilters();
    }
    setOpen(card, true);
    card.scrollIntoView({ behavior: reduceMotion ? "auto" : "smooth", block: "center" });
    if (!reduceMotion) {
      card.animate(
        [
          { boxShadow: "inset 0 0 0 2px rgba(169,217,79,.85)" },
          { boxShadow: "inset 0 0 0 2px rgba(169,217,79,0)" }
        ],
        { duration: 1400, easing: "ease-out" }
      );
    }
    if (history.replaceState) history.replaceState(null, "", "#" + id);
  }

  function bindCards() {
    document.addEventListener("click", function (e) {
      var head = e.target.closest(".vein__head");
      if (head) {
        var card = head.closest(".vein");
        setOpen(card, head.getAttribute("aria-expanded") !== "true");
        return;
      }

      var copy = e.target.closest("[data-copy]");
      if (copy) {
        var text = copy.getAttribute("data-copy");
        copyText(text).then(function (ok) {
          if (!ok) return;
          var prev = copy.textContent;
          copy.textContent = "Copied";
          copy.setAttribute("data-done", "1");
          toast("Copied to clipboard");
          setTimeout(function () {
            copy.textContent = prev;
            copy.removeAttribute("data-done");
          }, 1600);
        });
        return;
      }

      /* open everything on a shaft when its numeral is clicked */
      var num = e.target.closest(".shaft__num");
      if (num) {
        var sec = num.closest(".shaft");
        var cards = $$(".vein", sec).filter(function (c) { return !c.hidden; });
        var anyClosed = cards.some(function (c) { return $(".vein__head", c).getAttribute("aria-expanded") !== "true"; });
        cards.forEach(function (c) { setOpen(c, anyClosed); });
      }
    });
  }

  var toastTimer;
  function toast(msg) {
    var t = $("#toast");
    if (!t) return;
    t.textContent = msg;
    t.setAttribute("data-on", "1");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { t.removeAttribute("data-on"); }, 1700);
  }

  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text).then(function () { return true; }).catch(function () { return fallbackCopy(text); });
    }
    return Promise.resolve(fallbackCopy(text));
  }

  function fallbackCopy(text) {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.top = "-1000px";
    document.body.appendChild(ta);
    ta.select();
    var ok = false;
    try { ok = document.execCommand("copy"); } catch (err) { ok = false; }
    document.body.removeChild(ta);
    return ok;
  }

  /* ---------------- boot ---------------- */

  function boot() {
    renderShafts();
    renderCore();
    renderTailings();
    renderSealed();
    renderMethod();
    renderGithub();
    bindFilters();
    bindCards();
    applyFilters();

    /* "/" focuses search */
    document.addEventListener("keydown", function (e) {
      if (e.key !== "/" || e.metaKey || e.ctrlKey || e.altKey) return;
      var tag = (document.activeElement && document.activeElement.tagName) || "";
      if (/^(INPUT|TEXTAREA|SELECT)$/.test(tag)) return;
      var q = $("#q");
      if (!q) return;
      e.preventDefault();
      q.focus();
      q.select();
    });

    /* deep link */
    var hash = (location.hash || "").replace("#", "");
    if (hash) {
      var card = document.getElementById(hash);
      if (card && card.classList.contains("vein")) setTimeout(function () { jumpTo(hash); }, 60);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
