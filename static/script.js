/* ==========================================================================
   Finder's Central — Global Scripts
   - Light mode by default with localStorage persistence
   - Safe search & category filtering
   - Contact modal handling
   - Smooth entrance animations
   ========================================================================== */

// --- Theme Management ---
(function initTheme() {
    const savedTheme = localStorage.getItem("fc_theme") || "light";
    document.documentElement.setAttribute("data-theme", savedTheme);
    if (savedTheme === "dark") {
        document.body && document.body.classList.add("dark-theme");
    }
})();

document.addEventListener("DOMContentLoaded", () => {
    const themeToggle = document.getElementById("themeToggle");
    const currentTheme = localStorage.getItem("fc_theme") || "light";
    
    // Set initial icon
    if (themeToggle) {
        const iconSpan = themeToggle.querySelector(".theme-icon") || themeToggle;
        iconSpan.textContent = currentTheme === "dark" ? "☀️" : "🌙";
        
        themeToggle.addEventListener("click", () => {
            const activeTheme = document.documentElement.getAttribute("data-theme") || "light";
            const newTheme = activeTheme === "light" ? "dark" : "light";
            
            document.documentElement.setAttribute("data-theme", newTheme);
            if (newTheme === "dark") {
                document.body.classList.add("dark-theme");
                iconSpan.textContent = "☀️";
            } else {
                document.body.classList.remove("dark-theme");
                iconSpan.textContent = "🌙";
            }
            
            localStorage.setItem("fc_theme", newTheme);
        });
    }
});

// --- Search & Category Filtering ---
let activeCategory = "all";

function searchReports() {
    const searchInput = document.getElementById("searchInput");
    const query = searchInput ? searchInput.value.toLowerCase().trim() : "";
    const cards = document.querySelectorAll(".searchable-card");
    const noResultsMsg = document.getElementById("noResultsMessage");
    let visibleCount = 0;

    cards.forEach(card => {
        const cardCategory = card.getAttribute("data-category") || "";
        const cardText = card.innerText.toLowerCase();

        const matchesQuery = query === "" || cardText.includes(query);
        const matchesCategory = activeCategory === "all" || cardCategory.toLowerCase() === activeCategory.toLowerCase();

        if (matchesQuery && matchesCategory) {
            card.style.display = "flex";
            visibleCount++;
        } else {
            card.style.display = "none";
        }
    });

    if (noResultsMsg) {
        noResultsMsg.style.display = visibleCount === 0 ? "block" : "none";
    }
}

function filterCategory(category, buttonElement) {
    activeCategory = category;

    // Update active button state safely
    const buttons = document.querySelectorAll(".filter-btn");
    buttons.forEach(btn => btn.classList.remove("active"));
    
    if (buttonElement) {
        buttonElement.classList.add("active");
    } else {
        const matchedBtn = Array.from(buttons).find(btn => btn.textContent.trim().toLowerCase() === category.toLowerCase());
        if (matchedBtn) matchedBtn.classList.add("active");
    }

    // Trigger re-filtering with current search term
    searchReports();
}

// --- Contact Modal & Safe Email/Phone Handlers ---
function showCopyFeedback(msg) {
    const fb = document.getElementById("copyFeedback");
    if (fb) {
        fb.textContent = msg;
        setTimeout(() => {
            if (fb.textContent === msg) fb.textContent = "";
        }, 4000);
    }
}

function showContactOptions(phone, email, itemName, reportId) {
    const modal = document.getElementById("contactModal");
    const callBtn = document.getElementById("callBtn");
    const emailBtn = document.getElementById("emailBtn");
    const copyEmailBtn = document.getElementById("copyEmailBtn");
    const copyPhoneBtn = document.getElementById("copyPhoneBtn");
    const connectFromContactBtn = document.getElementById("requestConnectFromContactBtn");
    const infoEl = document.getElementById("contactModalItemInfo");

    if (infoEl) {
        infoEl.innerHTML = "Connecting regarding: <strong>" + (itemName || "Report") + "</strong>" + (reportId ? " (#" + reportId + ")" : "");
    }

    if (modal) {
        modal.style.display = "flex";
    }

    if (emailBtn) {
        const cleanName = itemName || "item";
        const cleanEmail = (email || "").trim();
        const subject = encodeURIComponent("Finder's Central: Inquiry regarding " + cleanName + (reportId ? " (Report #" + reportId + ")" : ""));
        const body = encodeURIComponent("Hello,\n\nI am contacting you regarding your report on Finder's Central for \"" + cleanName + "\".\n\nPlease let me know how we can coordinate.\n\nThank you!");
        
        emailBtn.onclick = function() {
            if (!cleanEmail) {
                showCopyFeedback("⚠️ No direct email address registered for this listing.");
                return;
            }
            window.location.href = "mailto:" + cleanEmail + "?subject=" + subject + "&body=" + body;
            showCopyFeedback("Opening mail client... If no client opens, use Copy Email below.");
        };
    }

    if (copyEmailBtn) {
        const cleanEmail = (email || "").trim();
        copyEmailBtn.onclick = function() {
            if (!cleanEmail) {
                showCopyFeedback("⚠️ No email address available to copy.");
                return;
            }
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(cleanEmail).then(() => {
                    showCopyFeedback("✓ Email address copied to clipboard!");
                }).catch(() => {
                    fallbackCopy(cleanEmail, () => showCopyFeedback("✓ Email copied: " + cleanEmail));
                });
            } else {
                fallbackCopy(cleanEmail, () => showCopyFeedback("✓ Email copied: " + cleanEmail));
            }
        };
    }

    if (callBtn) {
        callBtn.onclick = function() {
            window.location.href = "tel:" + phone;
        };
    }

    if (copyPhoneBtn) {
        copyPhoneBtn.onclick = function() {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(phone).then(() => {
                    showCopyFeedback("✓ Phone number copied to clipboard!");
                }).catch(() => {
                    showCopyFeedback("Phone: " + phone);
                });
            } else {
                showCopyFeedback("Phone: " + phone);
            }
        };
    }

    if (connectFromContactBtn) {
        connectFromContactBtn.onclick = function() {
            closeModal();
            openConnectModal(reportId, itemName, "");
        };
    }
}

function closeModal() {
    const modal = document.getElementById("contactModal");
    if (modal) {
        modal.style.display = "none";
    }
    const fb = document.getElementById("copyFeedback");
    if (fb) fb.textContent = "";
}

// --- Match Interest / Connection Request Modal Handlers ---
function openConnectModal(targetReportId, targetItemName, targetItemType, selectedSourceReportId) {
    const modal = document.getElementById("connectModal");
    const targetIdInput = document.getElementById("connectTargetId");
    const targetNameEl = document.getElementById("connectTargetName");
    const modalTitleEl = document.getElementById("connectModalTitle");
    const submitBtn = document.getElementById("connectSubmitBtn");
    const messageLabel = document.getElementById("connectMessageLabel");
    const messageInput = document.getElementById("connectMessage");
    const studentSelect = document.getElementById("studentSourceReport");
    const guestSelect = document.getElementById("guestSourceReport");

    if (targetIdInput) {
        targetIdInput.value = targetReportId;
    }
    if (targetNameEl) {
        targetNameEl.textContent = targetItemName ? targetItemName + (targetItemType ? " (" + targetItemType + ")" : "") : "Report #" + targetReportId;
    }

    const isFoundTarget = targetItemType && targetItemType.toLowerCase().includes("found");
    if (modalTitleEl) {
        modalTitleEl.textContent = isFoundTarget ? "🤝 Claim Found Item / Request Connection" : "🤝 Coordinate Handover with Searching Owner";
    }
    if (messageLabel) {
        messageLabel.textContent = isFoundTarget ? "Identifying Marks / Proof of Ownership:" : "Handover Instructions / Location Note:";
    }
    if (messageInput) {
        messageInput.placeholder = isFoundTarget ?
            "Describe specific identifying marks, serial numbers, wallpapers, contents, or circumstances to verify ownership safely..." :
            "Provide instructions on where or how the searching owner can collect or verify their item (e.g. security office, library desk)...";
    }
    if (submitBtn) {
        submitBtn.textContent = isFoundTarget ? "Send Claim / Verification Request" : "Send Handover Notification";
    }

    // Filter dropdown to show opposite item type if known
    const filterSelect = (selectEl) => {
        if (!selectEl) return;
        const options = selectEl.querySelectorAll("option");
        options.forEach(opt => {
            if (!opt.value) return;
            const optType = opt.getAttribute("data-type");
            if (targetItemType) {
                const oppositeType = targetItemType.toLowerCase().includes("lost") ? "Found Item" : "Lost Item";
                if (optType && optType.toLowerCase() !== oppositeType.toLowerCase()) {
                    opt.disabled = true;
                    opt.hidden = true;
                } else {
                    opt.disabled = false;
                    opt.hidden = false;
                }
            } else {
                opt.disabled = false;
                opt.hidden = false;
            }
        });
    };

    filterSelect(studentSelect);
    filterSelect(guestSelect);

    if (selectedSourceReportId) {
        if (studentSelect) {
            studentSelect.value = String(selectedSourceReportId);
        }
        if (guestSelect) {
            guestSelect.value = String(selectedSourceReportId);
        }
    }

    if (modal) {
        modal.style.display = "flex";
    }
}

function closeConnectModal() {
    const modal = document.getElementById("connectModal");
    if (modal) {
        modal.style.display = "none";
    }
}

// --- Robust Clipboard Helper with execCommand Fallback ---
function copyTextToClipboard(text, btnElement) {
    if (!text) return;
    const onSuccess = () => {
        if (btnElement) {
            const originalText = btnElement.getAttribute("data-original-text") || btnElement.innerText;
            btnElement.setAttribute("data-original-text", originalText);
            btnElement.innerText = "Copied! ✓";
            setTimeout(() => {
                btnElement.innerText = originalText;
            }, 2500);
        }
        if (typeof showCopyFeedback === "function") {
            showCopyFeedback("✓ Copied to clipboard!");
        }
    };

    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(onSuccess).catch(() => {
            fallbackCopy(text, onSuccess);
        });
    } else {
        fallbackCopy(text, onSuccess);
    }
}

function fallbackCopy(text, callback) {
    try {
        const textArea = document.createElement("textarea");
        textArea.value = text;
        textArea.style.position = "fixed";
        textArea.style.left = "-999999px";
        textArea.style.top = "-999999px";
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        const successful = document.execCommand("copy");
        document.body.removeChild(textArea);
        if (successful && callback) callback();
    } catch (err) {
        console.error("Clipboard copy failed", err);
    }
}

// --- Guest Claim Token URL Extraction before submit ---
document.addEventListener("DOMContentLoaded", () => {
    const connectForm = document.getElementById("connectForm");
    if (connectForm) {
        connectForm.addEventListener("submit", function(e) {
            const guestTokenInput = document.getElementById("guestClaimToken");
            if (guestTokenInput && guestTokenInput.value) {
                let token = guestTokenInput.value.trim();
                if (token.includes("/guest/claim/")) {
                    token = token.split("/guest/claim/")[1].split("?")[0].split("#")[0].trim();
                } else if (token.includes("/guest/manage/")) {
                    token = token.split("/guest/manage/")[1].split("?")[0].split("#")[0].trim();
                }
                guestTokenInput.value = token;
            }
        });
    }
});

// --- Scroll & Highlight Targeted Report ---
function highlightTargetReport() {
    let targetId = null;

    // Check query params ?highlight=ID or ?report_id=ID
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.has("highlight")) {
        targetId = urlParams.get("highlight");
    } else if (urlParams.has("report_id")) {
        targetId = urlParams.get("report_id");
    } else if (window.location.hash && window.location.hash.startsWith("#report-")) {
        targetId = window.location.hash.replace("#report-", "");
    }

    if (targetId) {
        // Reset category filter so item is visible
        if (typeof filterCategory === "function") {
            const allBtn = document.querySelector(".filter-btn");
            filterCategory("all", allBtn);
        }

        const card = document.getElementById("report-" + targetId);
        if (card) {
            setTimeout(() => {
                card.scrollIntoView({ behavior: "smooth", block: "center" });
                card.classList.add("report-card-highlighted");

                // Add targeted badge if not present
                if (!card.querySelector(".targeted-report-badge")) {
                    const badge = document.createElement("div");
                    badge.className = "targeted-report-badge";
                    badge.innerHTML = "🎯 Targeted Matching Report";
                    badge.style.cssText = "background: var(--primary); color: #ffffff; font-size: 0.75rem; font-weight: 700; padding: 4px 10px; border-radius: var(--radius-sm); margin-bottom: 10px; display: inline-flex; align-items: center; gap: 4px; box-shadow: var(--shadow-sm);";
                    const body = card.querySelector(".card-body");
                    if (body) {
                        body.insertBefore(badge, body.firstChild);
                    }
                }
            }, 200);
        }
    }
}

window.addEventListener("DOMContentLoaded", highlightTargetReport);
window.addEventListener("hashchange", highlightTargetReport);

// Modal Backdrop & Key listeners
window.addEventListener("click", (e) => {
    const contactModal = document.getElementById("contactModal");
    const connectModal = document.getElementById("connectModal");
    if (contactModal && e.target === contactModal) {
        closeModal();
    }
    if (connectModal && e.target === connectModal) {
        closeConnectModal();
    }
});

window.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
        closeModal();
        closeConnectModal();
    }
});

// --- Dynamic Category / Custom Category Handler ---
document.addEventListener("DOMContentLoaded", () => {
    const categorySelect = document.getElementById("category");
    const otherCategory = document.getElementById("other-category");
    const otherGroup = document.getElementById("other-category-group");

    if (categorySelect && otherCategory) {
        const toggleOther = () => {
            if (categorySelect.value === "Other") {
                if (otherGroup) otherGroup.style.display = "block";
                otherCategory.style.display = "block";
                otherCategory.required = true;
                otherCategory.focus();
            } else {
                if (otherGroup) otherGroup.style.display = "none";
                otherCategory.style.display = "none";
                otherCategory.required = false;
            }
        };
        categorySelect.addEventListener("change", toggleOther);
        // Run once on load to maintain state if browser re-populates form
        toggleOther();
    }
});

// --- Explainable Match Modal Handler ---
function openExplainModal(rep1Id, rep2Id, scorePct) {
    const modal = document.getElementById("explainModal");
    const titleEl = document.getElementById("explainModalTitle");
    const bodyEl = document.getElementById("explainModalBody");

    if (!modal || !bodyEl) return;

    if (titleEl) {
        titleEl.textContent = "Why this might be a match";
    }
    bodyEl.innerHTML = `<div style="text-align: center; padding: 24px; color: var(--text-muted);"><span style="font-size: 1.5rem; display: block; margin-bottom: 8px;">⏳</span>Comparing report details and checking possible match clues...</div>`;
    modal.style.display = "flex";

    const claimTokenInput = document.getElementById("guestClaimToken");
    const tokenQuery = claimTokenInput && claimTokenInput.value ? `&claim_token=${encodeURIComponent(claimTokenInput.value.trim())}` : "";

    fetch(`/api/match_explanation?rep1_id=${encodeURIComponent(rep1Id)}&rep2_id=${encodeURIComponent(rep2Id)}${tokenQuery}`)
        .then(async response => {
            if (!response.ok) {
                const errData = await response.json().catch(() => ({}));
                throw new Error(errData.error || `Server returned HTTP ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            renderExplainContent(data, rep1Id, rep2Id);
        })
        .catch(err => {
            bodyEl.innerHTML = `
                <div class="alert-box alert-error" style="margin-bottom: 14px;">
                    ⚠️ ${err.message}
                </div>
                <p style="font-size: 0.88rem; color: var(--text-secondary);">
                    Match explanations and verification clues are private to verified report owners and claimants.
                </p>
            `;
        });
}

function renderExplainContent(data, rep1Id, rep2Id) {
    const bodyEl = document.getElementById("explainModalBody");
    const titleEl = document.getElementById("explainModalTitle");
    if (titleEl) {
        titleEl.textContent = "Why this might be a match";
    }
    if (!bodyEl) return;

    let summaryHtml = "";
    if (data.summary_sentence) {
        summaryHtml = `
            <div style="background: var(--bg-surface-subtle); border-left: 3px solid var(--primary); padding: 10px 14px; border-radius: var(--radius-sm); margin-bottom: 14px;">
                <p style="margin: 0; font-size: 0.88rem; color: var(--text-primary); line-height: 1.45;">
                    ${data.summary_sentence}
                </p>
            </div>
        `;
    }

    let contraHtml = "";
    if (data.contradictions && data.contradictions.length > 0) {
        contraHtml = `
            <div style="background: var(--status-lost-bg); border-left: 3px solid var(--status-lost-text); padding: 10px 14px; border-radius: var(--radius-sm); margin: 12px 0;">
                <strong style="color: var(--status-lost-text); font-size: 0.85rem; display: block; margin-bottom: 4px;">⚠️ Differences to Check:</strong>
                <ul style="margin: 0; padding-left: 18px; font-size: 0.85rem; color: var(--status-lost-text); line-height: 1.45;">
                    ${data.contradictions.map(c => `<li>${c}</li>`).join("")}
                </ul>
            </div>
        `;
    }

    let componentsHtml = "";
    if (data.components && data.components.length > 0) {
        const rows = data.components.map(comp => {
            let statusColor = "var(--text-secondary)";
            if (comp.status === "match" || comp.status === "clean") statusColor = "var(--status-found-text)";
            else if (comp.status === "conflict") statusColor = "var(--status-lost-text)";

            return `
                <div class="match-component-row" style="display: flex; justify-content: space-between; align-items: center; padding: 6px 10px; border-radius: var(--radius-sm); background: var(--bg-surface-subtle); margin-bottom: 6px; font-size: 0.82rem; flex-wrap: wrap; gap: 4px;">
                    <div>
                        <strong style="color: var(--text-primary);">${comp.name}:</strong>
                        <span style="color: ${statusColor}; font-weight: 500; margin-left: 4px;">${comp.similarity}</span>
                    </div>
                    <div style="font-size: 0.76rem; color: var(--text-muted); display: flex; align-items: center; gap: 6px;">
                        <span>(${comp.weight})</span>
                        <strong style="color: ${comp.status === 'match' ? 'var(--primary)' : (comp.status === 'conflict' ? 'var(--status-lost-text)' : 'var(--text-muted)')};">${comp.contribution}</strong>
                    </div>
                </div>
            `;
        }).join("");

        componentsHtml = `
            <div style="margin: 14px 0;">
                <div style="font-size: 0.74rem; font-weight: 700; text-transform: uppercase; color: var(--text-muted); margin-bottom: 6px;">
                    Score Breakdown:
                </div>
                ${rows}
            </div>
        `;
    } else if (data.matching_attributes && data.matching_attributes.length > 0) {
        componentsHtml = `
            <div style="margin: 12px 0;">
                <div style="font-size: 0.74rem; font-weight: 700; text-transform: uppercase; color: var(--text-muted); margin-bottom: 6px;">
                    Why it might match:
                </div>
                <ul style="margin: 0; padding-left: 18px; font-size: 0.86rem; color: var(--text-secondary); line-height: 1.5;">
                    ${data.matching_attributes.map(a => `<li>${a}</li>`).join("")}
                </ul>
            </div>
        `;
    }

    let cluesHtml = "";
    if (data.verification_clues && data.verification_clues.length > 0) {
        cluesHtml = `
            <div style="background: var(--bg-surface-subtle); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); padding: 12px 14px; margin-bottom: 14px;">
                <strong style="font-size: 0.86rem; color: var(--text-primary); display: block; margin-bottom: 4px;">
                    🔍 What to check:
                </strong>
                <ul style="margin: 0; padding-left: 18px; font-size: 0.82rem; color: var(--text-secondary); line-height: 1.5;">
                    ${data.verification_clues.map(c => `<li>${c}</li>`).join("")}
                </ul>
            </div>
        `;
    }

    const disclaimer = data.disclaimer || "This score helps identify possible matches, not proof that the item is yours. It doesn't confirm ownership.";

    bodyEl.innerHTML = `
        ${summaryHtml}
        ${contraHtml}
        ${componentsHtml}
        ${cluesHtml}

        <div style="display: flex; justify-content: space-between; align-items: center; background: var(--bg-surface); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); padding: 10px 14px; flex-wrap: wrap; gap: 8px;">
            <div style="display: flex; align-items: center; gap: 8px;">
                <span style="font-size: 0.8rem; font-weight: 700; color: var(--text-muted); text-transform: uppercase;">Match Score:</span>
                <span style="font-size: 1.1rem; font-weight: 800; color: var(--primary);">${data.score_pct}</span>
            </div>
            <div style="font-size: 0.78rem; color: var(--text-muted);">
                ℹ️ ${disclaimer}
            </div>
        </div>
    `;
}

function closeExplainModal() {
    const modal = document.getElementById("explainModal");
    if (modal) modal.style.display = "none";
}

// Modal Backdrop listener update
window.addEventListener("click", (e) => {
    const contactModal = document.getElementById("contactModal");
    const connectModal = document.getElementById("connectModal");
    const explainModal = document.getElementById("explainModal");
    if (contactModal && e.target === contactModal) closeModal();
    if (connectModal && e.target === connectModal) closeConnectModal();
    if (explainModal && e.target === explainModal) closeExplainModal();
});

window.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
        closeModal();
        closeConnectModal();
        closeExplainModal();
    }
});

// --- File Preview Handler ---
function previewImage(event) {
    const preview = document.getElementById("preview-image");
    if (preview && event.target.files && event.target.files[0]) {
        preview.src = URL.createObjectURL(event.target.files[0]);
        preview.style.display = "block";
    }
}