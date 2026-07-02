const form = document.querySelector("#loginForm");
const button = document.querySelector("#loginButton");
const errorOutput = document.querySelector("#loginError");
const demoButton = document.querySelector("#demoButton");

async function openSession(path, options = {}) {
  const response = await fetch(path, options);
  const result = await response.json();
  if (!response.ok) {
    throw new Error(result.detail || "Sign in failed.");
  }
  window.location.replace(result.must_change_password ? "/change-password" : "/");
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  button.disabled = true;
  button.textContent = "Signing in...";
  errorOutput.textContent = "";

  try {
    await openSession("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: document.querySelector("#username").value,
        password: document.querySelector("#password").value,
      }),
    });
  } catch (error) {
    errorOutput.textContent = error.message;
  } finally {
    button.disabled = false;
    button.textContent = "Sign in";
  }
});

demoButton.addEventListener("click", async () => {
  demoButton.disabled = true;
  demoButton.textContent = "Opening demo...";
  errorOutput.textContent = "";
  try {
    await openSession("/api/auth/demo", { method: "POST" });
  } catch (error) {
    errorOutput.textContent = error.message;
    demoButton.disabled = false;
    demoButton.textContent = "Try public demo";
  }
});

fetch("/api/public-config")
  .then((response) => response.json())
  .then((config) => {
    if (config.public_demo) demoButton.classList.remove("hidden");
  })
  .catch(() => {});
