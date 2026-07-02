const form = document.querySelector("#changeForm");
const button = document.querySelector("#changeButton");
const errorOutput = document.querySelector("#changeError");
let csrfToken = "";

async function loadSession() {
  const response = await fetch("/api/auth/session");
  if (!response.ok) {
    window.location.replace("/login");
    return;
  }
  const session = await response.json();
  csrfToken = session.csrf_token;
  if (!session.must_change_password) {
    window.location.replace("/");
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorOutput.textContent = "";
  const newPassword = document.querySelector("#newPassword").value;
  const confirmation = document.querySelector("#confirmPassword").value;
  if (newPassword !== confirmation) {
    errorOutput.textContent = "Passwords do not match.";
    return;
  }

  button.disabled = true;
  button.textContent = "Updating...";
  try {
    const response = await fetch("/api/auth/change-password", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrfToken,
      },
      body: JSON.stringify({
        current_password: document.querySelector("#currentPassword").value,
        new_password: newPassword,
      }),
    });
    const result = await response.json();
    if (!response.ok) {
      throw new Error(result.detail || "Password update failed.");
    }
    window.location.replace("/");
  } catch (error) {
    errorOutput.textContent = error.message;
  } finally {
    button.disabled = false;
    button.textContent = "Update password";
  }
});

loadSession();
