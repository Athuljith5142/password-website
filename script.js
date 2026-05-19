const commonPasswords = new Set([
    "password", "123456", "12345678", "qwerty", "abc123", "admin", "letmein",
    "welcome", "monkey", "dragon", "login", "school", "college", "student",
    "pass", "1111", "0000", "1234", "4321", "iloveyou", "football"
]);

const dictionaryWords = [
    "admin", "school", "college", "student", "teacher", "password", "login",
    "welcome", "security", "system", "user", "name", "love", "home", "test"
];

const substitutions = {
    a: "A",
    e: "3",
    i: "1",
    l: "L",
    o: "0",
    s: "S",
    t: "7"
};

const compatibleSubstitutions = {
    a: "A",
    e: "3",
    i: "1",
    l: "L",
    o: "0",
    s: "5",
    t: "7"
};

const elements = {
    input: document.getElementById("passwordInput"),
    toggleVisibility: document.getElementById("toggleVisibility"),
    analyzeNow: document.getElementById("analyzeNow"),
    restrictedMode: document.getElementById("restrictedMode"),
    generateAlternative: document.getElementById("generateAlternative"),
    copySuggestion: document.getElementById("copySuggestion"),
    suggestionOutput: document.getElementById("suggestionOutput"),
    typingStatus: document.getElementById("typingStatus"),
    strengthFill: document.getElementById("strengthFill"),
    strengthLabel: document.getElementById("strengthLabel"),
    entropyValue: document.getElementById("entropyValue"),
    crackTime: document.getElementById("crackTime"),
    analysisText: document.getElementById("analysisText"),
    scoreRing: document.getElementById("scoreRing"),
    scoreValue: document.getElementById("scoreValue"),
    findingsList: document.getElementById("findingsList"),
    findingCount: document.getElementById("findingCount"),
    recommendationsList: document.getElementById("recommendationsList"),
    recommendationCount: document.getElementById("recommendationCount"),
    terminalLog: document.getElementById("terminalLog"),
    matrix: document.getElementById("matrix"),
    toast: document.getElementById("toast"),
    defenseControls: document.querySelectorAll(".defense-control"),
    defenseFill: document.getElementById("defenseFill"),
    defenseLevel: document.getElementById("defenseLevel"),
    defenseResult: document.getElementById("defenseResult")
};

let analysisTimers = [];
let statusTimer;
let latestSuggestion = "";
let previousDefenseScore = 0;

function secureIndex(max) {
    const cryptoApi = window.crypto || window.msCrypto;

    if (!cryptoApi || !cryptoApi.getRandomValues) {
        return Math.floor(Math.random() * max);
    }

    const randomValues = new Uint32Array(1);
    const limit = Math.floor(0xffffffff / max) * max;

    do {
        cryptoApi.getRandomValues(randomValues);
    } while (randomValues[0] >= limit);

    return randomValues[0] % max;
}

function addLog(message, type = "info") {
    const stamp = new Date().toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit"
    });
    const line = document.createElement("p");
    line.textContent = `[${stamp}] ${message}`;
    line.dataset.type = type;
    elements.terminalLog.prepend(line);

    while (elements.terminalLog.children.length > 10) {
        elements.terminalLog.lastElementChild.remove();
    }
}

function setStatus(message) {
    window.clearTimeout(statusTimer);
    elements.typingStatus.textContent = message;
    statusTimer = window.setTimeout(() => {
        elements.typingStatus.textContent = "Live scanner armed. Continue typing to rescan...";
    }, 1600);
}

function analyzeWithAnimation() {
    analysisTimers.forEach((timer) => window.clearTimeout(timer));
    analysisTimers = [];
    setStatus("Scanning Password Security...");
    addLog("Scanning Password Security...");

    analysisTimers.push(window.setTimeout(() => {
        setStatus("Checking Against Attack Patterns...");
        addLog("Checking Against Attack Patterns...");
    }, 120));

    analysisTimers.push(window.setTimeout(() => {
        setStatus("Analyzing Entropy...");
        addLog("Analyzing Entropy...");
        updateAnalysis();
    }, 260));
}

function getCharsetSize(password) {
    let size = 0;
    if (/[a-z]/.test(password)) size += 26;
    if (/[A-Z]/.test(password)) size += 26;
    if (/\d/.test(password)) size += 10;
    if (/[^A-Za-z0-9]/.test(password)) size += 33;
    return size;
}

function calculateEntropy(password) {
    const charsetSize = getCharsetSize(password);
    if (!password || charsetSize === 0) return 0;
    return Math.log2(charsetSize) * password.length;
}

function getCategoryCount(password) {
    return [
        /[a-z]/.test(password),
        /[A-Z]/.test(password),
        /\d/.test(password),
        /[^A-Za-z0-9]/.test(password)
    ].filter(Boolean).length;
}

function hasDangerFinding(findings) {
    return findings.some((finding) => finding.level === "danger");
}

function hasSequentialPattern(password) {
    const value = password.toLowerCase();
    const sequences = "abcdefghijklmnopqrstuvwxyz0123456789";

    for (let i = 0; i <= value.length - 3; i += 1) {
        const chunk = value.slice(i, i + 3);
        if (sequences.includes(chunk) || sequences.includes(chunk.split("").reverse().join(""))) {
            return true;
        }
    }

    return false;
}

function detectPatterns(password) {
    const lower = password.toLowerCase();
    const findings = [];

    if (!password) return findings;

    if (commonPasswords.has(lower)) {
        findings.push({
            level: "danger",
            text: "Common password detected. Attackers test this early."
        });
    }

    const dictionaryHit = dictionaryWords.find((word) => lower.includes(word) && lower !== word);
    if (dictionaryHit) {
        findings.push({
            level: "warning",
            text: `Dictionary word detected: "${dictionaryHit}".`
        });
    }

    if (/(.)\1{2,}/.test(password)) {
        findings.push({
            level: "danger",
            text: "Repeated characters found. Repetition reduces search complexity."
        });
    }

    if (hasSequentialPattern(password)) {
        findings.push({
            level: "danger",
            text: "Sequential numbers or letters detected."
        });
    }

    if (/^[A-Za-z]+$/.test(password)) {
        findings.push({
            level: "warning",
            text: "Letters-only password. Add digits or symbols."
        });
    }

    if (/^\d+$/.test(password)) {
        findings.push({
            level: "danger",
            text: "Numbers-only password. Numeric PINs are fast to brute force."
        });
    }

    if (/^[A-Z][a-z]+\d{1,2}$/.test(password)) {
        findings.push({
            level: "warning",
            text: "Predictable capitalization plus trailing number pattern."
        });
    }

    if (password.length < 8 && !elements.restrictedMode.checked) {
        findings.push({
            level: "danger",
            text: "Password is shorter than the recommended 8 character minimum."
        });
    }

    if (password.length <= 5 && elements.restrictedMode.checked && getCategoryCount(password) < 3) {
        findings.push({
            level: "warning",
            text: "Restricted mode needs at least three character types, such as lowercase, uppercase, and numbers."
        });
    }

    if (password.length <= 5 && elements.restrictedMode.checked && getCategoryCount(password) >= 3 && !hasDangerFinding(findings)) {
        findings.push({
            level: "success",
            text: "Restricted-mode compatible pattern detected: short, mixed-case, numeric, and symbol-free."
        });
    }

    if (!findings.length) {
        findings.push({
            level: "success",
            text: "No obvious weak attack patterns detected."
        });
    }

    return findings;
}

function buildRecommendations(password, findings, entropy) {
    const recommendations = [];

    if (!password) {
        return ["Enter a password to receive targeted recommendations."];
    }

    if (password.length < 12 && !elements.restrictedMode.checked) {
        recommendations.push("Use at least 12 characters when the system allows it.");
    }

    if (!/[A-Z]/.test(password)) recommendations.push("Add uppercase letters to increase the search space.");
    if (!/[a-z]/.test(password)) recommendations.push("Add lowercase letters to avoid a narrow character set.");
    if (!/\d/.test(password)) recommendations.push("Add numbers away from predictable endings.");
    if (!/[^A-Za-z0-9]/.test(password)) recommendations.push("If your system allows symbols, add one; otherwise use mixed casing and numbers.");

    if (findings.some((finding) => finding.level === "danger")) {
        recommendations.push("Remove dictionary words, repeated characters, and sequential patterns.");
    }

    if (elements.restrictedMode.checked) {
        recommendations.push("For 4-5 character limits, combine number substitution, mixed casing, and non-obvious order.");
        recommendations.push("Example: admin becomes ADm1N; school becomes SCh0L.");
        recommendations.push("Avoid memorable patterns like ab12, 1234, qwer, or name initials plus a digit.");
        recommendations.push("Short passwords need system protection: rate limiting, lockout, and MFA matter more than complexity alone.");
    }

    if (entropy >= 80) {
        recommendations.push("This password has solid entropy. Store it in a password manager if possible.");
    }

    return [...new Set(recommendations)].slice(0, 7);
}

function getDefenseState() {
    const enabled = [...elements.defenseControls].filter((control) => control.checked);
    const score = enabled.reduce((total, control) => total + Number(control.value), 0);

    return {
        enabled,
        score: Math.min(100, score)
    };
}

function getDefenseColor(score) {
    if (score < 45) return "var(--red)";
    if (score < 75) return "var(--yellow)";
    return "var(--green)";
}

function updateDefensePanel() {
    const { enabled, score } = getDefenseState();
    const enabledNames = enabled.map((control) => control.dataset.name);
    const missingRequired = ["Rate limiting", "Temporary lockout", "MFA"].filter((name) => !enabledNames.includes(name));

    elements.defenseFill.style.width = `${score}%`;
    elements.defenseFill.style.background = getDefenseColor(score);
    elements.defenseLevel.textContent = `${score}% protected`;

    if (score === 0) {
        elements.defenseResult.textContent = "Enable defenses to see brute-force protection guidance.";
    } else if (score < 45) {
        elements.defenseResult.textContent = `Low protection. Add ${missingRequired.join(", ") || "more controls"} to slow online guessing.`;
    } else if (score < 75) {
        elements.defenseResult.textContent = `Moderate protection. Enabled: ${enabledNames.join(", ")}. Add MFA and monitoring for stronger resistance.`;
    } else {
        elements.defenseResult.textContent = `Strong online brute-force protection. Enabled: ${enabledNames.join(", ")}. Keep logs reviewed and passwords hashed server-side.`;
    }

    if (score > previousDefenseScore) {
        addLog(`Brute-force defense improved to ${score}%.`, score >= 75 ? "success" : "warn");
    }

    previousDefenseScore = score;
}

function getStrength(password, entropy, findings) {
    if (elements.restrictedMode.checked && password.length >= 4 && password.length <= 5) {
        return getRestrictedStrength(password, entropy, findings);
    }

    let score = Math.min(100, Math.round((entropy / 100) * 88));
    const dangerCount = findings.filter((finding) => finding.level === "danger").length;
    const warningCount = findings.filter((finding) => finding.level === "warning").length;

    score -= dangerCount * 18;
    score -= warningCount * 8;
    if (password.length >= 12) score += 8;
    if (/[a-z]/.test(password) && /[A-Z]/.test(password) && /\d/.test(password) && /[^A-Za-z0-9]/.test(password)) score += 10;
    if (elements.restrictedMode.checked && password.length <= 5 && password.length >= 4) score += 8;

    score = Math.max(0, Math.min(100, score));

    if (!password) {
        return {
            score: 0,
            label: "Awaiting Input",
            color: "var(--red)",
            text: "Type a password to start live analysis.",
            crack: "No password entered"
        };
    }

    if (score < 45) {
        return {
            score,
            label: "Weak",
            color: "var(--red)",
            text: "Weak Password Detected. Use the recommendations to reduce obvious attack paths.",
            crack: estimateCrackTime(entropy)
        };
    }

    if (score < 75) {
        return {
            score,
            label: "Medium",
            color: "var(--yellow)",
            text: "Moderate security. Improve length, randomness, or character diversity.",
            crack: estimateCrackTime(entropy)
        };
    }

    return {
        score,
        label: "Strong",
        color: "var(--green)",
        text: "Secure Password Recommended. No major pattern risks were found.",
        crack: estimateCrackTime(entropy)
    };
}

function getRestrictedStrength(password, entropy, findings) {
    const categories = getCategoryCount(password);
    const dangerCount = findings.filter((finding) => finding.level === "danger").length;
    const warningCount = findings.filter((finding) => finding.level === "warning").length;
    let score = 38 + (password.length - 4) * 10 + categories * 14;

    score -= dangerCount * 24;
    score -= warningCount * 12;

    if (/^[A-Za-z0-9]+$/.test(password)) score += 6;
    if (/[a-z]/.test(password) && /[A-Z]/.test(password) && /\d/.test(password)) score += 8;
    if (!commonPasswords.has(password.toLowerCase()) && !hasSequentialPattern(password)) score += 6;

    score = Math.max(0, Math.min(88, score));

    if (score < 50) {
        return {
            score,
            label: "Weak",
            color: "var(--red)",
            text: "Weak Password Detected. Even with a short limit, avoid patterns, repeats, and common words.",
            crack: "Short-limit risk"
        };
    }

    if (score < 72) {
        return {
            score,
            label: "Medium",
            color: "var(--yellow)",
            text: "Usable for a restricted 4-5 character system, but add more mixing if possible.",
            crack: "Hardened short password"
        };
    }

    return {
        score,
        label: "Strong",
        color: "var(--green)",
        text: "Strong for a restricted 4-5 character system. It uses mixed casing, numbers, and avoids blocked symbols.",
        crack: "Optimized for short limit"
    };
}

function estimateCrackTime(entropy) {
    if (entropy <= 0) return "No password entered";

    const guessesPerSecond = 10000000000;
    const seconds = (2 ** Math.min(entropy, 128)) / guessesPerSecond / 2;

    if (seconds < 1) return "Instantly";
    if (seconds < 60) return `${Math.ceil(seconds)} seconds`;
    if (seconds < 3600) return `${Math.ceil(seconds / 60)} minutes`;
    if (seconds < 86400) return `${Math.ceil(seconds / 3600)} hours`;
    if (seconds < 31536000) return `${Math.ceil(seconds / 86400)} days`;
    if (seconds < 3153600000) return `${Math.ceil(seconds / 31536000)} years`;
    return "Centuries";
}

function renderList(list, items, emptyText) {
    list.innerHTML = "";

    if (!items.length) {
        const item = document.createElement("li");
        item.textContent = emptyText;
        list.append(item);
        return;
    }

    items.forEach((entry) => {
        const item = document.createElement("li");
        if (typeof entry === "string") {
            item.textContent = entry;
        } else {
            item.className = entry.level;
            item.textContent = entry.text;
        }
        list.append(item);
    });
}

function transformShortPassword(password) {
    const normalized = (password || "admin").toLowerCase();
    const examples = {
        admin: "ADm1N",
        school: "SCh0L",
        login: "L0g1N"
    };

    if (examples[normalized]) {
        return examples[normalized];
    }

    const targetLength = Math.min(5, Math.max(4, normalized.length || 4));
    const source = normalized.replace(/[^a-z0-9]/g, "").slice(0, targetLength).padEnd(targetLength, "x");
    const chars = source.split("").map((char, index) => {
        const replacement = compatibleSubstitutions[char] || char;
        if (index === 1 || index === 4) return replacement.toUpperCase();
        return replacement;
    });

    if (!chars.some((char) => /[A-Z]/.test(char))) {
        const alphaIndex = chars.findIndex((char) => /[a-z]/.test(char));
        chars[alphaIndex >= 0 ? alphaIndex : 0] = alphaIndex >= 0 ? chars[alphaIndex].toUpperCase() : "A";
    }

    if (!chars.some((char) => /[a-z]/.test(char))) {
        chars[targetLength - 1] = "u";
    }

    if (!chars.some((char) => /\d/.test(char))) {
        chars[Math.min(2, targetLength - 1)] = String(secureIndex(8) + 2);
    }

    return chars.join("").slice(0, targetLength);
}

function collapseRepeats(value) {
    return value.replace(/(.)\1{2,}/g, "$1$1");
}

function stylizeUserInput(password) {
    const cleaned = password.replace(/[^A-Za-z0-9]/g, "").replace(/(.)\1{2,}/g, "$1");
    const source = cleaned || "secure";

    return source.split("").map((char, index) => {
        const lower = char.toLowerCase();
        const substituted = compatibleSubstitutions[lower] && (index % 2 === 0 || commonPasswords.has(source.toLowerCase()))
            ? compatibleSubstitutions[lower]
            : char;

        if (/[a-z]/i.test(substituted) && index % 3 === 1) {
            return substituted.toUpperCase();
        }

        if (/[a-z]/i.test(substituted) && index % 3 === 2) {
            return substituted.toLowerCase();
        }

        return substituted;
    }).join("");
}

function generateRandomPassword(length) {
    const pool = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    return Array.from({ length }, () => pool[secureIndex(pool.length)]).join("");
}

function generateInputBasedPassword(password) {
    const core = collapseRepeats(stylizeUserInput(password));
    const prefixPool = ["N3o", "Cyb", "V4u", "Z3r", "Qx9"];
    const prefix = prefixPool[secureIndex(prefixPool.length)];
    const checksum = String((password.length * 7 + secureIndex(90) + 10) % 100).padStart(2, "0");
    const tail = generateRandomPassword(Math.max(4, 14 - core.length));

    return `${prefix}${core}${checksum}${tail}`.slice(0, 20);
}

function generateSuggestion(password) {
    if (elements.restrictedMode.checked || (password.length > 0 && password.length <= 5)) {
        return transformShortPassword(password);
    }

    if (!password) {
        return "";
    }

    return generateInputBasedPassword(password);
}

function updateAnalysis() {
    const password = elements.input.value;
    const entropy = calculateEntropy(password);
    const findings = detectPatterns(password);
    const recommendations = buildRecommendations(password, findings, entropy);
    const strength = getStrength(password, entropy, findings);

    latestSuggestion = generateSuggestion(password);

    elements.strengthLabel.textContent = strength.label;
    elements.entropyValue.textContent = `${entropy.toFixed(1)} bits entropy`;
    elements.crackTime.textContent = strength.crack;
    elements.analysisText.textContent = strength.text;
    elements.scoreValue.textContent = strength.score;
    elements.strengthFill.style.width = `${strength.score}%`;
    elements.strengthFill.style.background = strength.color;
    elements.scoreRing.style.setProperty("--score", `${strength.score * 3.6}deg`);
    elements.scoreRing.style.setProperty("--score-color", strength.color);
    elements.suggestionOutput.textContent = latestSuggestion || "Awaiting scan...";

    renderList(elements.findingsList, findings, "No findings.");
    renderList(elements.recommendationsList, recommendations, "No recommendations.");
    elements.findingCount.textContent = `${findings.length} findings`;
    elements.recommendationCount.textContent = `${recommendations.length} tips`;

    if (password && strength.label === "Weak") addLog("Weak Password Detected", "danger");
    if (password && strength.label === "Strong") addLog("Secure Password Recommended", "success");
}

function toggleVisibility() {
    const isHidden = elements.input.type === "password";
    elements.input.type = isHidden ? "text" : "password";
    elements.toggleVisibility.setAttribute("aria-label", isHidden ? "Hide password" : "Show password");
    elements.toggleVisibility.title = isHidden ? "Hide password" : "Show password";
}

async function copySuggestion() {
    if (!latestSuggestion) return;

    try {
        await navigator.clipboard.writeText(latestSuggestion);
    } catch (error) {
        const temporary = document.createElement("input");
        temporary.value = latestSuggestion;
        document.body.append(temporary);
        temporary.select();
        document.execCommand("copy");
        temporary.remove();
    }

    elements.toast.classList.add("show");
    window.setTimeout(() => elements.toast.classList.remove("show"), 2200);
    addLog("Secure suggestion copied to clipboard.", "success");
}

function buildMatrix() {
    const glyphs = "01#@$ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    for (let i = 0; i < 54; i += 1) {
        const drop = document.createElement("span");
        drop.textContent = glyphs[secureIndex(glyphs.length)];
        drop.style.left = `${secureIndex(100)}%`;
        drop.style.animationDuration = `${5 + secureIndex(10)}s`;
        drop.style.animationDelay = `${secureIndex(8000) / 1000}s`;
        elements.matrix.append(drop);
    }
}

function bindEvents() {
    elements.input.addEventListener("input", analyzeWithAnimation);
    elements.analyzeNow.addEventListener("click", analyzeWithAnimation);
    elements.toggleVisibility.addEventListener("click", toggleVisibility);
    elements.restrictedMode.addEventListener("change", () => {
        addLog(elements.restrictedMode.checked ? "Restricted Length Security Mode enabled." : "Restricted Length Security Mode disabled.");
        updateAnalysis();
    });
    elements.generateAlternative.addEventListener("click", () => {
        const suggestion = generateSuggestion(elements.input.value);

        if (!suggestion) {
            elements.suggestionOutput.textContent = "Enter a password first...";
            setStatus("Awaiting user input...");
            addLog("Suggestion skipped: no user input.", "warn");
            elements.input.focus();
            return;
        }

        if (suggestion.length >= 4 && suggestion.length <= 5 && !elements.restrictedMode.checked) {
            elements.restrictedMode.checked = true;
            addLog("Restricted Length Security Mode enabled for short alternative.");
        }

        elements.input.value = suggestion;
        updateAnalysis();
        latestSuggestion = suggestion;
        elements.suggestionOutput.textContent = suggestion;
        setStatus("Secure alternative applied to input");
        addLog("Generated and applied secure alternative.", "success");
    });
    elements.copySuggestion.addEventListener("click", copySuggestion);
    elements.defenseControls.forEach((control) => {
        control.addEventListener("change", updateDefensePanel);
    });
}

function init() {
    buildMatrix();
    bindEvents();
    addLog("Password analyzer initialized.");
    addLog("Scanning Password Security...");
    updateDefensePanel();
    updateAnalysis();
}

init();
