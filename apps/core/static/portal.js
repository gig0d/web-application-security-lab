"use strict";
const feedback = document.querySelector("#feedback");
const csrf = document.querySelector('meta[name="csrf-token"]')?.content;
const report = (text) => { if (feedback) feedback.textContent = text; };
async function api(path, method = "GET", body) {
  const headers = {};
  if (csrf) headers["X-CSRF-Token"] = csrf;
  if (body && !(body instanceof FormData)) headers["Content-Type"] = "application/json";
  const response = await fetch(path, { method, headers, body: body instanceof FormData ? body : body ? JSON.stringify(body) : undefined });
  const data = await response.json();
  if (!response.ok) throw new Error(data.detail || "The request could not be completed.");
  return data;
}
function bind(id, action) {
  const form = document.getElementById(id);
  form?.addEventListener("submit", async (event) => {
    event.preventDefault();
    try { await action(form, Object.fromEntries(new FormData(form))); }
    catch (error) { report(error.message); }
  });
}
bind("login", async (_, values) => { await api("/api/login", "POST", values); location.assign("/portal"); });
document.querySelector("#logout")?.addEventListener("click", async () => {
  try { await api("/api/logout", "POST"); location.assign("/"); } catch (error) { report(error.message); }
});
async function loadTickets(values = {}) {
  const target = document.querySelector("#tickets");
  if (!target) return;
  const rows = await api("/api/tickets?" + new URLSearchParams(values));
  target.replaceChildren();
  for (const ticket of rows) {
    const row = document.createElement("tr");
    const title = document.createElement("td");
    const link = document.createElement("a");
    link.href = "/tickets/" + ticket.id;
    link.textContent = "#" + ticket.id + "  " + ticket.title;
    title.append(link); row.append(title);
    for (const key of ["owner_id", "assignee_id", "status"]) {
      const cell = document.createElement("td"); cell.textContent = ticket[key] ?? "Unassigned"; row.append(cell);
    }
    target.append(row);
  }
  if (!rows.length) { const row = target.insertRow(); row.insertCell().textContent = "No matching tickets."; }
}
bind("filter", (_, values) => loadTickets(values));
bind("create-ticket", async (form, values) => { const ticket = await api("/api/tickets", "POST", values); location.assign("/tickets/" + ticket.id); });
bind("profile", async (_, values) => { await api("/api/profile", "POST", values); report("Profile saved."); });
bind("comment", async (form, values) => { await api(`/api/tickets/${form.dataset.ticket}/comments`, "POST", {body: values.body, private: values.private === "on"}); location.reload(); });
bind("ticket-status", async (form, values) => { await api(`/api/tickets/${form.dataset.ticket}`, "PATCH", values); location.reload(); });
bind("assign", async (form, values) => { await api(`/api/admin/tickets/${form.dataset.ticket}/assign`, "POST", { assignee_id: Number(values.assignee_id) }); location.reload(); });
async function loadAttachments() {
  const target = document.querySelector("#attachments");
  if (!target) return;
  const rows = await api(`/api/tickets/${target.dataset.ticket}/attachments`);
  target.replaceChildren();
  for (const item of rows) { const li = document.createElement("li"); const a = document.createElement("a"); a.href = "/api/attachments/" + item.id; a.textContent = item.filename; li.append(a); target.append(li); }
}
bind("upload", async (form) => { await api(`/api/tickets/${form.dataset.ticket}/attachments`, "POST", new FormData(form)); report("Document uploaded."); await loadAttachments(); });
document.querySelector("#preview")?.addEventListener("click", async () => {
  try { const result = await api("/api/preview?source=handbook"); document.querySelector("#preview-content").textContent = result.preview; } catch (error) { report(error.message); }
});
loadTickets().catch((error) => report(error.message));
loadAttachments().catch((error) => report(error.message));
