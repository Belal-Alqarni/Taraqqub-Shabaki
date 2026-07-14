const form = document.querySelector("#signupForm");
const button = document.querySelector("#signupButton");
const errorOutput = document.querySelector("#signupError");

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
    throw new Error(result.detail || "تعذر إنشاء الحساب. حاول مرة أخرى.");
  }
  return result;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  button.disabled = true;
  button.textContent = "جارٍ إنشاء الحساب...";
  errorOutput.textContent = "";

  try {
    const password = document.querySelector("#password").value;
    const confirmation = document.querySelector("#confirmPassword").value;
    if (password !== confirmation) {
      throw new Error("كلمتا المرور غير متطابقتين.");
    }

    await request("/api/auth/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        workspace_name: document.querySelector("#workspaceName").value,
        username: document.querySelector("#username").value,
        password,
      }),
    });
    window.location.replace("/");
  } catch (error) {
    errorOutput.textContent = error.message;
    button.disabled = false;
    button.textContent = "إنشاء الحساب";
  }
});
