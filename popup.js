const message = document.querySelector("#message");
const scanButton = document.querySelector("#scan");

async function requireLogin() {
  try {
    const { loggedIn } = await chrome.storage.local.get("loggedIn");
    if (!loggedIn) window.location.replace("login.html");
  } catch {
    message.textContent = "Could not check sign-in status. Please reopen the extension.";
    scanButton.disabled = true;
  }
}

document.querySelector("#logout").addEventListener("click", async () => {
  try {
    await chrome.storage.local.remove(["loggedIn", "remembered"]);
    window.location.href = "login.html";
  } catch {
    message.textContent = "Could not sign out. Please try again.";
  }
});

scanButton.addEventListener("click", async () => {
  message.textContent = "Scanning current page...";
  scanButton.disabled = true;
  try {
    const { loggedIn } = await chrome.storage.local.get("loggedIn");
    if (!loggedIn) {
      window.location.replace("login.html");
      return;
    }

    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) throw new Error("NO_TAB");
    if (!tab.url || !/^https?:/.test(tab.url)) throw new Error("UNSCANNABLE");

    const [injection] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => {
        const text = document.body?.innerText || "";
        const links = [...document.querySelectorAll("a[href]")].map((link) => link.href);
        const senderMatch = text.match(/\bFrom:\s*([^\n]+)/i);
        return { text, links, sender: senderMatch?.[1] || "" };
      }
    });
    if (!injection?.result || typeof injection.result.text !== "string" || !Array.isArray(injection.result.links)) {
      throw new Error("INVALID_DATA");
    }
    if (!injection.result.text.trim() && injection.result.links.length === 0) throw new Error("EMPTY_PAGE");

    const result = EmailThreatScanner.analyze(injection.result);
    showResult(result, tab.title || tab.url);
    message.textContent = "";
  } catch (error) {
    const messages = {
      NO_TAB: "No active tab was found.",
      UNSCANNABLE: "This page cannot be scanned. Open a regular website and try again.",
      EMPTY_PAGE: "No visible page text or links were found.",
      INVALID_DATA: "The page returned data that could not be scanned."
    };
    message.textContent = messages[error.message] || "Could not scan this page. It may block extension access.";
  } finally {
    scanButton.disabled = false;
  }
});

function showResult(result, title) {
  const panel = document.querySelector("#result");
  panel.hidden = false;
  panel.classList.toggle("suspicious", result.level === "SUSPICIOUS");
  panel.classList.toggle("high-risk", result.level === "HIGH RISK");
  document.querySelector("#level").textContent = result.level;
  document.querySelector("#score").textContent = result.score;
  document.querySelector("#page-title").textContent = title;
  const reasons = document.querySelector("#reasons");
  reasons.replaceChildren();
  for (const reason of result.reasons) {
    const item = document.createElement("li");
    item.textContent = reason;
    reasons.append(item);
  }
  if (!result.reasons.length) {
    const item = document.createElement("li");
    item.textContent = "No common threat signals detected";
    reasons.append(item);
  }
}

requireLogin();