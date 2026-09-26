const form = document.querySelector("#login-form");
const message = document.querySelector("#message");

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  message.textContent = "";

  const email = document.querySelector("#email").value.trim().toLowerCase();
  const password = document.querySelector("#password").value;
  if (email !== "demo@example.com" || password !== "demo123") {
    message.textContent = "Email or password is incorrect.";
    return;
  }

  try {
    await chrome.storage.local.set({ loggedIn: true, remembered: document.querySelector("#remember").checked });
    window.location.href = "popup.html";
  } catch {
    message.textContent = "Could not save your sign-in. Please try again.";
  }
});

document.querySelector("#forgot").addEventListener("click", () => {
  message.textContent = "Use the demo account shown with the extension.";
  message.style.color = "#a9efbc";
});