const form = document.querySelector("#loginForm");
const button = document.querySelector("#loginButton");
const errorOutput = document.querySelector("#loginError");
const demoButton = document.querySelector("#demoButton");
const signupLink = document.querySelector("#signupLink");

const wait = (milliseconds) =>
  new Promise((resolve) => window.setTimeout(resolve, milliseconds));

async function request(path, options = {}, retries = 2) {
  const response = await fetch(path, options);
  const body = await response.text();

  if (
    !response.ok &&
    retries > 0 &&
    response.headers.get("x-render-routing") === "no-server"
  ) {
    await wait(800);
    return request(path, options, retries - 1);
  }

  let result = {};
  try {
    result = body ? JSON.parse(body) : {};
  } catch {
    result = {};
  }

  if (!response.ok) {
    throw new Error(result.detail || "Service is waking up. Please try again.");
  }
  return result;
}

async function openSession(path, options = {}) {
  const result = await request(path, options);
  window.location.replace(result.must_change_password ? "/change-password" : "/");
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  button.disabled = true;
  button.textContent = "جارٍ تسجيل الدخول...";
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
    button.textContent = "تسجيل الدخول";
  }
});

demoButton.addEventListener("click", async () => {
  demoButton.disabled = true;
  demoButton.textContent = "جارٍ فتح العرض...";
  errorOutput.textContent = "";
  try {
    await openSession("/api/auth/demo", { method: "POST" });
  } catch (error) {
    errorOutput.textContent = error.message;
    demoButton.disabled = false;
    demoButton.textContent = "تجربة العرض العام";
  }
});

request("/api/public-config")
  .then((config) => {
    if (config.public_demo) demoButton.classList.remove("hidden");
    if (config.allow_signup) signupLink.classList.remove("hidden");
  })
  .catch(() => {});
