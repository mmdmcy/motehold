const noteForm = document.querySelector("#noteForm");
const noteInput = document.querySelector("#noteInput");
const sendButton = document.querySelector("#sendButton");
const refreshButton = document.querySelector("#refreshButton");
const messageList = document.querySelector("#messageList");
const emptyState = document.querySelector("#emptyState");
const connection = document.querySelector(".connection");
const connectionLabel = document.querySelector("#connectionLabel");

const icons = {
  copy: `
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <rect x="8" y="8" width="14" height="14" rx="2"></rect>
      <path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"></path>
    </svg>
  `,
  check: `
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M20 6 9 17l-5-5"></path>
    </svg>
  `,
  trash: `
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M3 6h18"></path>
      <path d="M8 6V4h8v2"></path>
      <path d="M19 6l-1 16H6L5 6"></path>
      <path d="M10 11v6"></path>
      <path d="M14 11v6"></path>
    </svg>
  `
};

let messages = [];
let copiedId = null;
let copiedTimer = null;

function setConnection(label, online) {
  connectionLabel.textContent = label;
  connection.classList.toggle("is-offline", !online);
}

function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(date);
}

function renderMessages() {
  messageList.textContent = "";
  emptyState.hidden = messages.length > 0;

  for (const message of messages) {
    const article = document.createElement("article");
    article.className = "message";

    const content = document.createElement("div");

    const text = document.createElement("p");
    text.className = "message-text";
    text.textContent = message.body;

    const meta = document.createElement("div");
    meta.className = "message-meta";
    meta.textContent = formatDate(message.created_at);

    content.append(text, meta);

    const actions = document.createElement("div");
    actions.className = "message-actions";

    const copyButton = document.createElement("button");
    copyButton.type = "button";
    copyButton.className = "icon-button";
    copyButton.title = "Copy";
    copyButton.setAttribute("aria-label", "Copy message");
    copyButton.innerHTML = copiedId === message.id ? icons.check : icons.copy;
    copyButton.classList.toggle("is-copied", copiedId === message.id);
    copyButton.addEventListener("click", () => copyMessage(message));

    const deleteButton = document.createElement("button");
    deleteButton.type = "button";
    deleteButton.className = "icon-button is-danger";
    deleteButton.title = "Delete";
    deleteButton.setAttribute("aria-label", "Delete message");
    deleteButton.innerHTML = icons.trash;
    deleteButton.addEventListener("click", () => deleteMessage(message.id));

    actions.append(copyButton, deleteButton);
    article.append(content, actions);
    messageList.append(article);
  }
}

async function loadMessages() {
  const response = await fetch("/api/messages", { cache: "no-store" });
  if (!response.ok) throw new Error("Could not load messages");
  const data = await response.json();
  messages = Array.isArray(data.messages) ? data.messages : [];
  renderMessages();
}

async function sendMessage(event) {
  event.preventDefault();
  const body = noteInput.value;
  if (!body.trim()) {
    noteInput.focus();
    return;
  }

  sendButton.disabled = true;
  try {
    const response = await fetch("/api/messages", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ body })
    });
    if (!response.ok) throw new Error("Could not send message");
    noteInput.value = "";
    noteInput.focus();
    await loadMessages();
  } finally {
    sendButton.disabled = false;
  }
}

async function deleteMessage(id) {
  const response = await fetch(`/api/messages/${id}`, { method: "DELETE" });
  if (!response.ok) return;
  messages = messages.filter((message) => message.id !== id);
  renderMessages();
}

async function copyMessage(message) {
  await copyText(message.body);
  copiedId = message.id;
  window.clearTimeout(copiedTimer);
  copiedTimer = window.setTimeout(() => {
    copiedId = null;
    renderMessages();
  }, 1100);
  renderMessages();
}

async function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return;
  }

  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.top = "-1000px";
  textarea.style.left = "-1000px";
  document.body.append(textarea);
  textarea.focus();
  textarea.select();
  document.execCommand("copy");
  textarea.remove();
}

function connectEvents() {
  if (!window.EventSource) return;

  const source = new EventSource("/events");
  source.onopen = () => setConnection("Live", true);
  source.onerror = () => setConnection("Reconnecting", false);
  source.onmessage = (event) => {
    try {
      const payload = JSON.parse(event.data);
      if (payload.type !== "hello") loadMessages().catch(() => {});
    } catch {
      loadMessages().catch(() => {});
    }
  };
}

noteForm.addEventListener("submit", sendMessage);
refreshButton.addEventListener("click", () => loadMessages().catch(() => setConnection("Offline", false)));

loadMessages()
  .then(() => setConnection("Live", true))
  .catch(() => setConnection("Offline", false));
connectEvents();
