(() => {
  const suspiciousPhrases = [
    ["verify your account", "Account verification request detected"],
    ["login immediately", "Immediate login request detected"],
    ["account suspended", "Account suspension warning detected"],
    ["click here", "Call to click a link detected"],
    ["congratulations", "Unexpected reward language detected"],
    ["urgent", "Urgent language detected"],
    ["password", "Password-related request detected"],
    ["payment", "Payment-related language detected"],
    ["bank", "Bank-related language detected"],
    ["otp", "One-time passcode request detected"],
    ["prize", "Prize or reward language detected"]
  ];
  const shorteners = ["bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "shorturl.at"];

  function inspectUrl(value) {
    let url;
    try {
      url = new URL(value);
    } catch {
      return null;
    }
    return url;
  }

  function analyze(data) {
    if (!data || typeof data.text !== "string" || !Array.isArray(data.links)) {
      throw new TypeError("Invalid scan data");
    }

    const reasons = new Set();
    let score = 0;
    const add = (points, reason) => {
      score += points;
      reasons.add(reason);
    };
    const text = data.text.toLowerCase();
    let phraseHits = 0;
    for (const [phrase, reason] of suspiciousPhrases) {
      if (text.includes(phrase)) {
        phraseHits += 1;
        reasons.add(reason);
      }
    }
    if (phraseHits) score += Math.min(3, phraseHits);

    for (const value of data.links.slice(0, 200)) {
      if (typeof value !== "string") continue;
      const url = inspectUrl(value);
      if (!url || !["http:", "https:"].includes(url.protocol)) continue;
      const host = url.hostname.toLowerCase();
      let linkSignals = 0;
      if (url.protocol === "http:") {
        linkSignals += 1;
        reasons.add("Link uses an unencrypted HTTP connection");
      }
      if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)) {
        linkSignals += 2;
        reasons.add("Link uses an IP address instead of a domain");
      }
      if (shorteners.some((domain) => host === domain || host.endsWith(`.${domain}`))) {
        linkSignals += 2;
        reasons.add("Link uses a URL shortener");
      }
      if (/login|verify|secure|account|update|confirm|wallet|billing/.test(`${host}${url.pathname}`)) {
        linkSignals += 1;
        reasons.add("Link contains a sensitive or misleading URL pattern");
      }
      if (host.split(".").length > 4) {
        linkSignals += 1;
        reasons.add("Link has an unusually large number of subdomains");
      }
      score += linkSignals;
    }

    if (typeof data.sender === "string" && data.sender.trim()) {
      const sender = data.sender.toLowerCase();
      const match = sender.match(/@([a-z0-9.-]+)/);
      const domain = match?.[1]?.replace(/[^a-z0-9.-].*$/, "");
      if (/xn--|^(?:\d{1,3}\.){3}\d{1,3}$/.test(domain || "") || /secure|verify|account|support/.test(domain || "")) {
        add(2, "Sender domain has a suspicious pattern");
      }
    }

    score = Math.min(score, 99);
    const level = score >= 6 ? "HIGH RISK" : score >= 3 ? "SUSPICIOUS" : "SAFE";
    return { level, score, reasons: [...reasons] };
  }

  globalThis.EmailThreatScanner = { analyze };
})();