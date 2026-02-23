// wiki-loader.js - Wiki loader (flat data structure)
// P29-B rewrite: 2026-02-23

(function() {
    "use strict";

    var currentArticleId = null;
    var groupedData = null;

    // Category display order
    var CATEGORY_ORDER = [
        { id: "overview",    label: "概要" },
        { id: "process",     label: "プロセス解析" },
        { id: "memory",      label: "メモリ解析" },
        { id: "network",     label: "ネットワーク解析" },
        { id: "fileinspect", label: "ファイル検査" },
        { id: "persistence", label: "永続化メカニズム" },
        { id: "artifacts",   label: "システムアーティファクト" },
        { id: "references",  label: "参考資料" }
    ];

    function groupByCategory(data) {
        var groups = {};
        for (var i = 0; i < data.length; i++) {
            var catId = data[i].categoryId;
            if (!groups[catId]) groups[catId] = [];
            groups[catId].push(data[i]);
        }
        return groups;
    }

    function wikiInit() {
        var tree = document.getElementById("wiki-tree");
        if (!tree || typeof WIKI_DATA === "undefined") return;
        groupedData = groupByCategory(WIKI_DATA);
        tree.innerHTML = "";
        renderTree(tree);
    }

    function renderTree(container) {
        for (var c = 0; c < CATEGORY_ORDER.length; c++) {
            var cat = CATEGORY_ORDER[c];
            var articles = groupedData[cat.id];
            if (!articles || articles.length === 0) continue;

            var catHeader = document.createElement("div");
            catHeader.className = "wiki-tree-category";
            catHeader.textContent = cat.label;
            catHeader.setAttribute("data-cat-id", cat.id);
            container.appendChild(catHeader);

            for (var a = 0; a < articles.length; a++) {
                var art = articles[a];
                var item = document.createElement("div");
                item.className = "wiki-tree-item";
                item.setAttribute("data-article-id", art.id);
                item.setAttribute("data-cat-id", cat.id);
                item.textContent = art.title;
                item.onclick = (function(id) {
                    return function() {
                        showArticle(id);
                        highlightTreeItem(id);
                    };
                })(art.id);
                container.appendChild(item);
            }
        }
    }

    function showArticle(articleId) {
        currentArticleId = articleId;
        var article = findArticle(articleId);
        var viewer = document.getElementById("wiki-article");
        if (!article || !viewer) return;
        var ct = article.content;
        var html = "";
        html += '<div class="wiki-article-title">' + escHtml(article.title) + "</div>";

        var sections = [
            {key: "summary",     icon: "\ud83d\udccb", title: "概要",                   cls: ""},
            {key: "points",      icon: "\u26a0\ufe0f", title: "異常が出やすいポイント", cls: ""},
            {key: "logic",       icon: "\ud83d\udd27", title: "このツールの検出ロジック", cls: ""},
            {key: "flow_danger", icon: "\ud83d\udd34", title: "異常判定の業務フロー",   cls: "flow-danger"},
            {key: "flow_safe",   icon: "\ud83d\udfe2", title: "正常判定の業務フロー",   cls: "flow-safe"},
            {key: "mitre",       icon: "\ud83c\udfaf", title: "MITRE ATT&CK マッピング", cls: "mitre-box"},
            {key: "references",  icon: "\ud83d\udcda", title: "出典・参考資料",         cls: ""}
        ];

        for (var i = 0; i < sections.length; i++) {
            var s = sections[i];
            if (ct[s.key]) {
                var bodyClass = "wiki-section-body" + (s.cls ? " " + s.cls : "");
                html += '<div class="wiki-article-section">';
                html += '<div class="wiki-section-heading">' + s.icon + " " + s.title + "</div>";
                html += '<div class="' + bodyClass + '">' + formatText(ct[s.key]) + "</div>";
                html += "</div>";
            }
        }
        viewer.innerHTML = html;
        viewer.scrollTop = 0;
    }

    function filterTree(query) {
        query = (query || "").toLowerCase();
        var catHeaders = document.querySelectorAll(".wiki-tree-category");
        var items = document.querySelectorAll(".wiki-tree-item");
        var visibleCats = {};

        for (var i = 0; i < items.length; i++) {
            var el = items[i];
            var text = el.textContent.toLowerCase();
            var aid = el.getAttribute("data-article-id");
            var catId = el.getAttribute("data-cat-id");
            var contentMatch = false;
            if (query !== "") {
                var art = findArticle(aid);
                if (art && art.content) {
                    var keys = Object.keys(art.content);
                    for (var k = 0; k < keys.length; k++) {
                        var val = art.content[keys[k]];
                        if (typeof val === "string" && val.toLowerCase().indexOf(query) !== -1) {
                            contentMatch = true; break;
                        }
                    }
                }
            }
            if (query === "" || text.indexOf(query) !== -1 || contentMatch) {
                el.style.display = "block";
                visibleCats[catId] = true;
            } else {
                el.style.display = "none";
            }
        }

        for (var j = 0; j < catHeaders.length; j++) {
            var cid = catHeaders[j].getAttribute("data-cat-id");
            catHeaders[j].style.display = visibleCats[cid] ? "block" : "none";
        }
    }

    function highlightTreeItem(articleId) {
        var all = document.querySelectorAll(".wiki-tree-item");
        for (var i = 0; i < all.length; i++) all[i].classList.remove("active");
        var t = document.querySelector('[data-article-id="' + articleId + '"]');
        if (t) t.classList.add("active");
    }

    function findArticle(articleId) {
        if (typeof WIKI_DATA === "undefined") return null;
        for (var i = 0; i < WIKI_DATA.length; i++) {
            if (WIKI_DATA[i].id === articleId) return WIKI_DATA[i];
        }
        return null;
    }

    function formatText(text) {
        if (!text) return "";
        var escaped = escHtml(text);
        escaped = escaped.replace(/^\u30FB/gm, '<span style="color:var(--accent-info,#60a5fa);">\u25B8</span> ');
        escaped = escaped.replace(/^(\d+\.\s)/gm, '<span style="color:var(--accent-primary,#a78bfa);font-weight:bold;">$1</span>');
        return escaped.replace(/\n/g, "<br>");
    }

    function escHtml(str) {
        if (!str) return "";
        return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
    }

    window.wikiInit = wikiInit;
    window.wikiShowArticle = showArticle;
    window.filterTree = filterTree;
})();
