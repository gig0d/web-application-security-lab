"use strict";
const token = document.querySelector('meta[name="aegis-token"]').content;
const feedback = document.querySelector("#feedback");
async function mutate(path, method, data) {
  const response = await fetch(path, {method, headers: {"Content-Type": "application/json", "X-Aegis-Token": token}, body: data ? JSON.stringify(data) : undefined});
  const result = await response.json();
  if (!response.ok) throw new Error(result.detail || "Operation failed");
  return result;
}
function bind(id, action) {
  const form = document.getElementById(id);
  form?.addEventListener("submit", async (event) => {
    event.preventDefault(); const button = form.querySelector("button"); button.disabled = true;
    try { await action(form, Object.fromEntries(new FormData(form))); }
    catch (error) { feedback.textContent = error.message; }
    finally { button.disabled = false; }
  });
}
bind("progress", async (form, values) => { await mutate("/api/progress/" + form.dataset.lab, "POST", {notes: values.notes, reviewed: values.reviewed === "on"}); feedback.textContent = "Notebook saved. Verification status is unchanged."; });
bind("evaluate", async (form, values) => { document.querySelector("#evaluation").textContent = "Running bounded local checks…"; const result = await mutate("/api/evaluate/" + form.dataset.lab, "POST", values); document.querySelector("#evaluation").textContent = JSON.stringify(result, null, 2); feedback.textContent = "Execution recorded: " + result.status; });
bind("reset-data", async (_, values) => { const result = await mutate("/api/reset-data", "POST", values); feedback.textContent = JSON.stringify(result); });
document.querySelector("#reset-progress")?.addEventListener("click", async (event) => { try { await mutate("/api/progress/" + event.target.dataset.lab, "DELETE"); location.reload(); } catch (error) { feedback.textContent = error.message; } });
document.querySelector("#lab-filter")?.addEventListener("input", (event) => { const query = event.target.value.toLowerCase(); document.querySelectorAll(".lab-card").forEach((card) => { card.hidden = !card.dataset.search.toLowerCase().includes(query); }); });
