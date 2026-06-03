const appShell = document.querySelector("#appShell");
const sidebarToggleButton = document.querySelector("#sidebarToggleButton");
const sidebarCloseButton = document.querySelector("#sidebarCloseButton");
const showChannelFormButton = document.querySelector("#showChannelFormButton");
const channelForm = document.querySelector("#channelForm");
const channelInput = document.querySelector("#channelInput");
const channelList = document.querySelector("#channelList");
const channelHeading = document.querySelector("#channelHeading");
const noteForm = document.querySelector("#noteForm");
const noteInput = document.querySelector("#noteInput");
const imageInput = document.querySelector("#imageInput");
const imageButton = document.querySelector("#imageButton");
const imagePreview = document.querySelector("#imagePreview");
const imagePreviewThumb = document.querySelector("#imagePreviewThumb");
const removeImageButton = document.querySelector("#removeImageButton");
const sendButton = document.querySelector("#sendButton");
const refreshButton = document.querySelector("#refreshButton");
const messageList = document.querySelector("#messageList");
const emptyState = document.querySelector("#emptyState");
const connection = document.querySelector(".connection");
const connectionLabel = document.querySelector("#connectionLabel");
const confirmDialog = document.querySelector("#confirmDialog");
const confirmTitle = document.querySelector("#confirmTitle");
const confirmMessage = document.querySelector("#confirmMessage");
const confirmCancelButton = document.querySelector("#confirmCancelButton");
const confirmAcceptButton = document.querySelector("#confirmAcceptButton");

const maxImageBytes = 5 * 1024 * 1024;
const allowedImageTypes = new Set(["image/gif", "image/jpeg", "image/png", "image/webp"]);

const storageKeys = {
  activeChannel: "motehold.activeChannelId",
  sidebar: "motehold.sidebar"
};

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
  hash: `
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M4 9h16"></path>
      <path d="M4 15h16"></path>
      <path d="M10 3 8 21"></path>
      <path d="m16 3-2 18"></path>
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

let channels = [];
let messages = [];
let activeChannelId = null;
let copiedId = null;
let copiedTimer = null;
let selectedImage = null;
let selectedImagePreviewUrl = null;
let pendingConfirm = null;

function readStorage(key) {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

function writeStorage(key, value) {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    return;
  }
}

function setSidebarOpen(open) {
  appShell.classList.toggle("is-sidebar-collapsed", !open);
  writeStorage(storageKeys.sidebar, open ? "open" : "closed");
}

function getStoredChannelId() {
  const value = Number.parseInt(readStorage(storageKeys.activeChannel) || "", 10);
  return Number.isFinite(value) ? value : null;
}

function setConnection(label, online) {
  connectionLabel.textContent = label;
  connection.classList.toggle("is-offline", !online);
}

function activeChannel() {
  return channels.find((channel) => channel.id === activeChannelId) || null;
}

function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(date);
}

function renderActiveChannel() {
  const channel = activeChannel();
  channelHeading.textContent = channel ? `# ${channel.name}` : "";
  noteInput.placeholder = channel ? `Message #${channel.name}` : "Paste or type a note";
  sendButton.disabled = !channel;
}

function renderChannels() {
  channelList.textContent = "";

  for (const channel of channels) {
    const row = document.createElement("div");
    row.className = "channel-row";
    row.classList.toggle("is-active", channel.id === activeChannelId);

    const button = document.createElement("button");
    button.type = "button";
    button.className = "channel-button";
    button.title = channel.name;
    button.setAttribute("aria-label", `Open ${channel.name}`);
    button.addEventListener("click", () => selectChannel(channel.id));

    const hash = document.createElement("span");
    hash.className = "channel-icon";
    hash.innerHTML = icons.hash;

    const name = document.createElement("span");
    name.className = "channel-name";
    name.textContent = channel.name;

    const count = document.createElement("span");
    count.className = "channel-count";
    count.textContent = String(channel.message_count || 0);

    button.append(hash, name, count);

    const deleteButton = document.createElement("button");
    deleteButton.type = "button";
    deleteButton.className = "icon-button compact channel-delete";
    deleteButton.title = "Delete channel";
    deleteButton.setAttribute("aria-label", `Delete ${channel.name}`);
    deleteButton.innerHTML = icons.trash;
    deleteButton.addEventListener("click", (event) => {
      event.stopPropagation();
      deleteChannel(channel);
    });

    row.append(button, deleteButton);
    channelList.append(row);
  }

  renderActiveChannel();
}

function renderMessages() {
  messageList.textContent = "";
  emptyState.hidden = messages.length > 0;

  for (const message of messages) {
    const article = document.createElement("article");
    article.className = "message";

    const content = document.createElement("div");

    if (message.body) {
      const text = document.createElement("p");
      text.className = "message-text";
      text.textContent = message.body;
      content.append(text);
    }

    if (message.image_url) {
      const image = document.createElement("img");
      image.className = "message-image";
      image.src = message.image_url;
      image.alt = "Image attachment";
      image.loading = "lazy";
      content.append(image);
    }

    const meta = document.createElement("div");
    meta.className = "message-meta";
    meta.textContent = formatDate(message.created_at);

    content.append(meta);

    const actions = document.createElement("div");
    actions.className = "message-actions";

    if (message.body) {
      const copyButton = document.createElement("button");
      copyButton.type = "button";
      copyButton.className = "icon-button";
      copyButton.title = "Copy";
      copyButton.setAttribute("aria-label", "Copy message");
      copyButton.innerHTML = copiedId === message.id ? icons.check : icons.copy;
      copyButton.classList.toggle("is-copied", copiedId === message.id);
      copyButton.addEventListener("click", () => copyMessage(message));
      actions.append(copyButton);
    }

    const deleteButton = document.createElement("button");
    deleteButton.type = "button";
    deleteButton.className = "icon-button is-danger";
    deleteButton.title = "Delete";
    deleteButton.setAttribute("aria-label", "Delete message");
    deleteButton.innerHTML = icons.trash;
    deleteButton.addEventListener("click", () => deleteMessage(message));

    actions.append(deleteButton);
    article.append(content, actions);
    messageList.append(article);
  }
}

async function loadChannels() {
  const response = await fetch("/api/channels", { cache: "no-store" });
  if (!response.ok) throw new Error("Could not load channels");
  const data = await response.json();
  channels = Array.isArray(data.channels) ? data.channels : [];

  const preferredId = activeChannelId || getStoredChannelId();
  const preferredChannel = channels.find((channel) => channel.id === preferredId);
  activeChannelId = preferredChannel ? preferredChannel.id : channels[0]?.id || null;

  if (activeChannelId) {
    writeStorage(storageKeys.activeChannel, String(activeChannelId));
  }

  renderChannels();
}

async function loadMessages(retry = true) {
  if (!activeChannelId) {
    messages = [];
    renderMessages();
    return;
  }

  const url = `/api/messages?channel_id=${encodeURIComponent(activeChannelId)}`;
  const response = await fetch(url, { cache: "no-store" });
  if (response.status === 404 && retry) {
    activeChannelId = null;
    await loadChannels();
    await loadMessages(false);
    return;
  }
  if (!response.ok) throw new Error("Could not load messages");
  const data = await response.json();
  messages = Array.isArray(data.messages) ? data.messages : [];
  renderMessages();
}

async function refreshAll() {
  await loadChannels();
  await loadMessages();
}

async function selectChannel(channelId) {
  if (activeChannelId === channelId) return;
  activeChannelId = channelId;
  copiedId = null;
  writeStorage(storageKeys.activeChannel, String(channelId));
  renderChannels();
  await loadMessages();

  if (window.matchMedia("(max-width: 760px)").matches) {
    setSidebarOpen(false);
  }
  noteInput.focus();
}

function reportChannelInputError(message) {
  channelInput.setCustomValidity(message);
  channelInput.reportValidity();
}

async function createChannel(event) {
  event.preventDefault();
  const name = channelInput.value;
  if (!name.trim()) {
    channelInput.focus();
    return;
  }

  channelInput.setCustomValidity("");
  showChannelFormButton.disabled = true;
  try {
    const response = await fetch("/api/channels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name })
    });
    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      const message = data.error === "channel_exists"
        ? "Channel already exists."
        : "Could not create channel.";
      reportChannelInputError(message);
      return;
    }

    channelInput.value = "";
    channelForm.hidden = true;
    activeChannelId = data.channel?.id || null;
    await refreshAll();
    noteInput.focus();
  } finally {
    showChannelFormButton.disabled = false;
  }
}

async function deleteChannel(channel) {
  if (channels.length <= 1) {
    await showNotice({
      title: "Cannot delete channel",
      message: "Create another channel before deleting this one."
    });
    return;
  }

  const confirmed = await confirmAction({
    title: "Delete channel?",
    message: `#${channel.name} and all of its messages will be deleted.`,
    confirmLabel: "Delete"
  });
  if (!confirmed) return;

  const response = await fetch(`/api/channels/${channel.id}`, { method: "DELETE" });
  if (response.status === 409) {
    await showNotice({
      title: "Cannot delete channel",
      message: "Create another channel before deleting this one."
    });
    return;
  }
  if (!response.ok) {
    await showNotice({
      title: "Delete failed",
      message: "The channel could not be deleted."
    });
    return;
  }
  if (activeChannelId === channel.id) activeChannelId = null;
  await refreshAll();
}

function fileToDataUrl(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.addEventListener("load", () => resolve(reader.result));
    reader.addEventListener("error", () => reject(reader.error));
    reader.readAsDataURL(file);
  });
}

function clearSelectedImage() {
  selectedImage = null;
  imageInput.value = "";
  imagePreview.hidden = true;
  imagePreviewThumb.removeAttribute("src");
  if (selectedImagePreviewUrl) {
    URL.revokeObjectURL(selectedImagePreviewUrl);
    selectedImagePreviewUrl = null;
  }
}

async function selectImage() {
  const file = imageInput.files?.[0];
  if (!file) {
    clearSelectedImage();
    return;
  }

  if (!allowedImageTypes.has(file.type)) {
    clearSelectedImage();
    await showNotice({
      title: "Unsupported image",
      message: "Use PNG, JPEG, GIF, or WebP."
    });
    return;
  }

  if (file.size > maxImageBytes) {
    clearSelectedImage();
    await showNotice({
      title: "Image too large",
      message: "Images can be up to 5 MB."
    });
    return;
  }

  if (selectedImagePreviewUrl) URL.revokeObjectURL(selectedImagePreviewUrl);
  selectedImage = file;
  selectedImagePreviewUrl = URL.createObjectURL(file);
  imagePreviewThumb.src = selectedImagePreviewUrl;
  imagePreview.hidden = false;
}

async function sendMessage(event) {
  event.preventDefault();
  const body = noteInput.value;
  if ((!body.trim() && !selectedImage) || !activeChannelId) {
    noteInput.focus();
    return;
  }

  sendButton.disabled = true;
  try {
    const image = selectedImage
      ? {
          type: selectedImage.type,
          data_url: await fileToDataUrl(selectedImage)
        }
      : undefined;
    const response = await fetch("/api/messages", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ body, channel_id: activeChannelId, image })
    });
    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      const message = data.error === "image_too_large"
        ? "Images can be up to 5 MB."
        : "Could not send message.";
      await showNotice({ title: "Send failed", message });
      return;
    }
    noteInput.value = "";
    clearSelectedImage();
    noteInput.focus();
    await refreshAll();
  } finally {
    sendButton.disabled = false;
    renderActiveChannel();
  }
}

async function deleteMessage(message) {
  const confirmed = await confirmAction({
    title: "Delete message?",
    message: "This message will be permanently deleted.",
    confirmLabel: "Delete"
  });
  if (!confirmed) return;

  const response = await fetch(`/api/messages/${message.id}`, { method: "DELETE" });
  if (!response.ok) {
    await showNotice({
      title: "Delete failed",
      message: "The message could not be deleted."
    });
    return;
  }
  messages = messages.filter((item) => item.id !== message.id);
  renderMessages();
  await loadChannels();
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
      if (payload.type !== "hello") refreshAll().catch(() => {});
    } catch {
      refreshAll().catch(() => {});
    }
  };
}

function closeDialog(result) {
  if (!pendingConfirm) return;
  const { resolve, previousFocus } = pendingConfirm;
  pendingConfirm = null;
  confirmDialog.hidden = true;
  confirmAcceptButton.classList.add("danger-button");
  confirmAcceptButton.classList.remove("secondary-button");
  confirmCancelButton.hidden = false;
  if (previousFocus && typeof previousFocus.focus === "function") previousFocus.focus();
  resolve(result);
}

function confirmAction({ title, message, confirmLabel = "Confirm" }) {
  if (pendingConfirm) closeDialog(false);

  const previousFocus = document.activeElement;
  confirmTitle.textContent = title;
  confirmMessage.textContent = message;
  confirmAcceptButton.textContent = confirmLabel;
  confirmCancelButton.textContent = "Cancel";
  confirmCancelButton.hidden = false;
  confirmAcceptButton.classList.add("danger-button");
  confirmAcceptButton.classList.remove("secondary-button");

  return new Promise((resolve) => {
    pendingConfirm = {
      resolve,
      previousFocus
    };
    confirmDialog.hidden = false;
    confirmAcceptButton.focus();
  });
}

function showNotice({ title, message }) {
  if (pendingConfirm) closeDialog(false);

  const previousFocus = document.activeElement;
  confirmTitle.textContent = title;
  confirmMessage.textContent = message;
  confirmAcceptButton.textContent = "OK";
  confirmCancelButton.hidden = true;
  confirmAcceptButton.classList.remove("danger-button");
  confirmAcceptButton.classList.add("secondary-button");

  return new Promise((resolve) => {
    pendingConfirm = {
      resolve,
      previousFocus
    };
    confirmDialog.hidden = false;
    confirmAcceptButton.focus();
  });
}

sidebarToggleButton.addEventListener("click", () => {
  const collapsed = appShell.classList.contains("is-sidebar-collapsed");
  setSidebarOpen(collapsed);
});
sidebarCloseButton.addEventListener("click", () => setSidebarOpen(false));
showChannelFormButton.addEventListener("click", () => {
  channelForm.hidden = !channelForm.hidden;
  if (!channelForm.hidden) channelInput.focus();
});
channelInput.addEventListener("input", () => channelInput.setCustomValidity(""));
channelForm.addEventListener("submit", createChannel);
imageButton.addEventListener("click", () => imageInput.click());
imageInput.addEventListener("change", () => selectImage());
removeImageButton.addEventListener("click", clearSelectedImage);
noteForm.addEventListener("submit", sendMessage);
refreshButton.addEventListener("click", () => {
  refreshAll().catch(() => setConnection("Offline", false));
});
confirmCancelButton.addEventListener("click", () => closeDialog(false));
confirmAcceptButton.addEventListener("click", () => closeDialog(true));
confirmDialog.addEventListener("click", (event) => {
  if (event.target === confirmDialog) closeDialog(false);
});
window.addEventListener("keydown", (event) => {
  if (!pendingConfirm || event.key !== "Escape") return;
  event.preventDefault();
  closeDialog(false);
});

setSidebarOpen(readStorage(storageKeys.sidebar) !== "closed");
refreshAll()
  .then(() => setConnection("Live", true))
  .catch(() => setConnection("Offline", false));
connectEvents();
