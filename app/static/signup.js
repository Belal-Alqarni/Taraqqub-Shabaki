const form = document.querySelector("#signupForm");
const button = document.querySelector("#signupButton");
const errorOutput = document.querySelector("#signupError");

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  button.disabled = true;
  button.textContent = "Creating...";
  errorOutput.textContent = "";

  try {
    const response = await fetch("/api/auth/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        workspace_name: document.querySelector("#workspaceName").value,
        username: document.querySelector("#username").value,
        password: document.querySelector("#password").value,
      }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.detail || "Account creation failed.");
    window.location.replace("/");
  } catch (error) {
    errorOutput.textContent = error.message;
    button.disabled = false;
    button.textContent = "Create account";
  }
});
