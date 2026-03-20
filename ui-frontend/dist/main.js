const { invoke } = window.__TAURI__.tauri;

const APP_DISPLAY_NAME = 'FerrumVault';
const APP_REPO_URL = 'https://github.com/satishkumarvenkatasamy/ferrumvault-public';
const USER_GUIDE_URL = 'https://github.com/satishkumarvenkatasamy/ferrumvault-public/blob/main/docs/user-guide.md';

const PASSWORD_DISPLAY_SECONDS_DEFAULT = 20; // TODO: make user-configurable in settings
const HISTORY_PASSWORD_DISPLAY_SECONDS = 15;
const PASSWORD_SESSION_MIN_MINUTES = 1;
const PASSWORD_SESSION_MAX_MINUTES = 30;
const PASSWORD_SESSION_DEFAULT_MINUTES = 5;
const SESSION_TIMEOUT_SECONDS = 5 * 60;
const SESSION_MIN_REAUTH_SECONDS = 60;
const SEARCH_DEBOUNCE_MS = 220;
const TOAST_SUCCESS_MS = 5000;
const TOAST_ERROR_MS = 10000;
const AUTH_REQUIRED_DIALOGS = new Set(['sync-upload', 'sync-import']);
const CONNECT_GOOGLE_HELPER =
  'Connect to Google Drive first (☰ → Settings → Connect with Google) before syncing or importing.';

const state = {
  folderFilter: null,
  tagFilter: null,
  searchText: "",
  snapshot: null,
  authenticated: false,
  selectedCredentialId: null,
  requiresSetup: false,
  revealedPassword: null,
  editMode: false,
  editDraft: null,
  passwordEditing: false,
  passwordTimerId: null,
  passwordCountdown: 0,
  creatingNew: false,
  placeholderCredential: null,
  pendingNew: false,
  toastTimerId: null,
  menuOpen: false,
  activeDialog: null,
  importBundles: [],
  selectedBundleId: null,
  oauthState: null,
  historyEntries: [],
  historySecrets: {},
  historyReveal: false,
  historyView: false,
  historyTimerId: null,
  historyCountdown: 0,
  sessionSecondsRemaining: 0,
  sessionTimerId: null,
  dialogCloseHandler: null,
  vaultContext: {
    baseDir: '',
    profile: 'default',
    profilePath: '',
    profileExists: false,
    initialized: false,
    availableProfiles: [],
  },
  advancedPanelOpen: false,
  syncConfigured: false,
  appInfo: {
    name: APP_DISPLAY_NAME,
    version: null,
  },
};

const refs = {};
let searchDebounceId = null;
let autoCapObserver = null;
let dialogProgressTimerId = null;
let dialogProgressHideTimeoutId = null;

function $(selector) {
  return document.querySelector(selector);
}

function escapeHtml(value) {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function escapeAttr(value) {
  return (value || '').replace(/"/g, '&quot;');
}

function formatDisplayUrl(url) {
  if (!url) return '';
  return url.replace(/^https?:\/\//i, '').replace(/\/$/, '');
}

function renderCopyButton(value, label, variant = 'small') {
  if (!value) return '';
  return `
    <button class="copy-chip ${variant}" data-copy="${escapeAttr(value)}" data-copy-label="${escapeAttr(label)}" title="Copy ${label}">📋 Copy</button>
  `;
}

function markNoAutoCap(element) {
  if (!element || typeof element.getAttribute !== 'function') {
    return;
  }
  const tag = element.tagName;
  if (tag !== 'INPUT' && tag !== 'TEXTAREA') {
    return;
  }
  const type = (element.getAttribute('type') || '').toLowerCase();
  const textTypes = ['', 'text', 'search', 'password', 'email', 'url', 'number', 'tel'];
  const isTextual = tag === 'TEXTAREA' || textTypes.includes(type);
  if (!isTextual) {
    return;
  }
  element.setAttribute('autocapitalize', 'none');
  element.setAttribute('autocorrect', 'off');
  if (type !== 'password') {
    element.setAttribute('spellcheck', 'false');
  }
}

function applyNoAutoCap(root) {
  if (!root) return;
  if (root.nodeType === Node.ELEMENT_NODE) {
    markNoAutoCap(root);
  }
  if (typeof root.querySelectorAll === 'function') {
    root.querySelectorAll('input, textarea').forEach(markNoAutoCap);
  }
}

async function loadAppMetadata() {
  const appApi = window.__TAURI__?.app;
  const defaultInfo = { name: APP_DISPLAY_NAME, version: null };
  if (!appApi) {
    state.appInfo = defaultInfo;
    return;
  }
  try {
    const [name, version] = await Promise.all([
      typeof appApi.getName === 'function' ? appApi.getName() : Promise.resolve(APP_DISPLAY_NAME),
      typeof appApi.getVersion === 'function' ? appApi.getVersion() : Promise.resolve(null),
    ]);
    state.appInfo = {
      name: name || APP_DISPLAY_NAME,
      version: version || null,
    };
  } catch (err) {
    console.error('Unable to load app metadata', err);
    state.appInfo = defaultInfo;
  }
}

async function openExternalLink(url) {
  if (!url) return;
  const shellApi = window.__TAURI__?.shell;
  try {
    if (shellApi && typeof shellApi.open === 'function') {
      await shellApi.open(url);
    } else {
      window.open(url, '_blank', 'noreferrer');
    }
  } catch (err) {
    console.error('Unable to open external link', err);
  }
}

async function copyLinkToClipboard(url, label = 'Link') {
  if (!url) return;
  try {
    if (navigator?.clipboard?.writeText) {
      await navigator.clipboard.writeText(url);
    } else {
      const textarea = document.createElement('textarea');
      textarea.value = url;
      textarea.setAttribute('readonly', 'true');
      textarea.style.position = 'absolute';
      textarea.style.left = '-9999px';
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
    }
    showToast({ type: 'success', title: 'Copied', message: `${label} copied to clipboard.` });
  } catch (err) {
    console.error('Unable to copy link', err);
    showToast({ type: 'error', title: 'Copy failed', message: 'Could not copy link.' });
  }
}

function initAutoCapControl() {
  applyNoAutoCap(document);
  if (autoCapObserver || typeof MutationObserver === 'undefined') {
    return;
  }
  autoCapObserver = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      mutation.addedNodes.forEach((node) => {
        if (node.nodeType === Node.ELEMENT_NODE) {
          applyNoAutoCap(node);
        }
      });
    });
  });
  if (document.body) {
    autoCapObserver.observe(document.body, { childList: true, subtree: true });
  }
}

function splitList(value, forceLower = false) {
  if (!value) return [];
  return value
    .split(",")
    .map((item) => item.trim())
    .filter((item) => item.length > 0)
    .map((item) => (forceLower ? item.toLowerCase() : item));
}

function computeFilteredStats() {
  if (!state.snapshot || !state.snapshot.credentials) {
    return { folders: {}, tags: {}, totalFiltered: 0 };
  }
  const stats = { folders: {}, tags: {}, totalFiltered: 0 };
  state.snapshot.credentials.forEach((cred) => {
    const folderName = cred.folder || "general";
    stats.folders[folderName] = (stats.folders[folderName] || 0) + 1;
    if (Array.isArray(cred.tags)) {
      cred.tags.forEach((tag) => {
        stats.tags[tag] = (stats.tags[tag] || 0) + 1;
      });
    }
    stats.totalFiltered += 1;
  });
  return stats;
}

function formatError(err) {
  if (typeof err === "string") {
    return err.replace(/_/g, " ");
  }
  if (err && err.message) {
    return err.message;
  }
  return "Operation failed";
}

function formatFriendlyTimestamp(isoString) {
  if (!isoString) {
    return { short: 'Never', tooltip: '' };
  }
  const date = new Date(isoString);
  if (Number.isNaN(date.getTime())) {
    return { short: isoString, tooltip: isoString };
  }
  const day = date.getDate().toString().padStart(2, '0');
  const month = new Intl.DateTimeFormat('en-US', { month: 'short' }).format(date);
  const year = date.getFullYear();
  const time = new Intl.DateTimeFormat('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: true,
  })
    .format(date)
    .toLowerCase();
  const short = `${day}-${month}-${year} ${time}`;
  const longDate = new Intl.DateTimeFormat('en-US', {
    weekday: 'long',
    month: 'long',
    day: 'numeric',
    year: 'numeric',
  }).format(date);
  const full = `${longDate} ${time}`;
  return { short, tooltip: full };
}

function resetDetailState() {
  state.revealedPassword = null;
  state.editMode = false;
  state.editDraft = null;
  state.passwordEditing = false;
  stopPasswordTimer();
  state.passwordCountdown = 0;
  removePlaceholderCredential();
  state.creatingNew = false;
  state.placeholderCredential = null;
  state.historyEntries = [];
  state.historySecrets = {};
  state.historyReveal = false;
  state.historyView = false;
  stopHistoryTimer();
  state.historyCountdown = 0;
}


function removePlaceholderCredential() {
  if (!state.placeholderCredential || !state.snapshot) return;
  state.snapshot.credentials = state.snapshot.credentials.filter(
    (cred) => cred.cred_id !== state.placeholderCredential.cred_id
  );
}

function stopPasswordTimer() {
  if (state.passwordTimerId) {
    window.clearInterval(state.passwordTimerId);
    state.passwordTimerId = null;
  }
}

function startPasswordTimer() {
  if (state.passwordEditing) {
    return;
  }
  stopPasswordTimer();
  state.passwordCountdown = PASSWORD_DISPLAY_SECONDS_DEFAULT;
  state.passwordTimerId = window.setInterval(() => {
    if (state.passwordCountdown <= 1) {
      hidePassword();
      return;
    }
    state.passwordCountdown -= 1;
    renderDetail();
  }, 1000);
}

function hidePassword() {
  stopPasswordTimer();
  state.revealedPassword = null;
  state.passwordCountdown = 0;
  state.passwordEditing = false;
  renderDetail();
}

function stopHistoryTimer() {
  if (state.historyTimerId) {
    window.clearInterval(state.historyTimerId);
    state.historyTimerId = null;
  }
}

function startHistoryTimer() {
  stopHistoryTimer();
  state.historyCountdown = HISTORY_PASSWORD_DISPLAY_SECONDS;
  state.historyTimerId = window.setInterval(() => {
    if (!state.historyReveal) {
      stopHistoryTimer();
      return;
    }
    if (state.historyCountdown <= 1) {
      hideHistoryPasswords();
      return;
    }
    state.historyCountdown -= 1;
    rerenderDetailPreservingScroll();
  }, 1000);
}

function hideHistoryPasswords() {
  stopHistoryTimer();
  if (!state.historyReveal && state.historyCountdown === 0) {
    return;
  }
  state.historyReveal = false;
  state.historyCountdown = 0;
  rerenderDetailPreservingScroll();
}

function setupRefs() {
  refs.appShell = document.getElementById("app-shell");
  refs.loginScreen = document.getElementById("login-screen");
  refs.loginForm = document.getElementById("login-form");
  refs.loginPassword = document.getElementById("login-password");
  refs.loginStatus = document.getElementById("login-status");
  refs.loginError = refs.loginStatus;
  refs.loginTitle = document.getElementById("login-title");
  refs.loginSubtitle = document.getElementById("login-subtitle");
  refs.loginConfirm = document.getElementById("login-confirm");
  refs.loginContextProfile = document.getElementById("login-context-profile");
  refs.loginContextFolder = document.getElementById("login-context-folder");
  refs.loginSubtitleProfile = document.getElementById("login-subtitle-profile");
  refs.loginLocationInfo = document.getElementById("login-location-info");
  refs.appContextBar = document.getElementById("app-context-bar");
  refs.appStatusTray = document.getElementById("app-status-tray");
  refs.appSessionProgress = document.getElementById("app-session-progress");
  refs.vaultAdvancedToggle = document.getElementById("vault-advanced-toggle");
  refs.vaultAdvancedPanel = document.getElementById("vault-advanced-panel");
  refs.vaultBaseDir = document.getElementById("vault-base-dir");
  refs.vaultProfile = document.getElementById("vault-profile");
  refs.vaultProfileOptions = document.getElementById("vault-profile-options");
  refs.vaultApply = document.getElementById("vault-apply");
  refs.vaultReset = document.getElementById("vault-reset");
  refs.vaultContextStatus = document.getElementById("vault-context-status");
  refs.logoutBtn = document.getElementById("logout-btn");
  refs.clearFolderBtn = document.getElementById("clear-folder-filter");
  refs.clearTagBtn = document.getElementById("clear-tag-filter");
  refs.clearSearchBtn = document.getElementById("clear-search-filter");
  refs.folderList = document.getElementById("folder-list");
  refs.tagList = document.getElementById("tag-list");
  refs.credentialList = document.getElementById("credential-list");
  if (refs.credentialList) {
    refs.credentialList.classList.add("credential-list");
  }
  refs.detailPane = document.getElementById("detail-pane");
  refs.folderSearch = document.getElementById("folder-search");
  refs.credentialSearch = document.getElementById("credential-search");
  refs.globalSearch = document.getElementById("global-search");
  refs.breadcrumb = document.getElementById("breadcrumb");
  refs.newCredentialBtn = document.getElementById("new-credential-btn");
  refs.toastHost = document.getElementById("toast-host");
  refs.menuButton = document.getElementById("menu-button");
  refs.menuDropdown = document.getElementById("menu-dropdown");
  refs.modalBackdrop = document.getElementById("modal-backdrop");
  refs.modalTitle = document.getElementById("modal-title");
  refs.modalContent = document.getElementById("modal-content");
  refs.modalClose = document.getElementById("modal-close");
  refs.modalDismiss = document.getElementById("modal-dismiss");
  updateSessionProgressBars();
  renderLoginContextStack();
}

async function fetchSnapshot() {
  if (!state.authenticated) return false;
  setListLoading(true);
  try {
    const snapshot = await invoke("load_snapshot", {
      folder: state.folderFilter,
      tag: state.tagFilter,
      search: state.searchText,
    });
    state.snapshot = snapshot;
    state.selectedCredentialId = snapshot.selected ? snapshot.selected.cred_id : null;
    resetDetailState();
    if (state.selectedCredentialId) {
      await loadPasswordHistory(state.selectedCredentialId);
    }
    render();
    setListLoading(false);
    return true;
  } catch (err) {
    setListLoading(false);
    if (String(err).includes("NOT_AUTHENTICATED")) {
      state.authenticated = false;
      toggleView();
    }
    console.error("Failed to load snapshot", err);
    return false;
  }
}

function setListLoading(isLoading) {
  if (!refs.credentialList) return;
  if (isLoading) {
    refs.credentialList.classList.add("skeleton");
  } else {
    refs.credentialList.classList.remove("skeleton");
  }
}

function showToast({ type = 'success', title = '', message = '', timeoutMs } = {}) {
  if (!refs.toastHost) return;
  clearToast();
  const duration = timeoutMs ?? (type === 'error' ? TOAST_ERROR_MS : TOAST_SUCCESS_MS);
  const role = type === 'error' ? 'alert' : 'status';
  const icon = type === 'error' ? '⚠️' : '✅';
  refs.toastHost.innerHTML = `
    <div class="toast ${type}" role="${role}">
      <div class="toast-icon">${icon}</div>
      <div class="toast-body">
        <div class="toast-title">${escapeHtml(title)}</div>
        <div class="toast-message">${escapeHtml(message)}</div>
      </div>
      <button class="toast-close" aria-label="Close">✕</button>
      <div class="toast-progress"></div>
    </div>
  `;
  const closeBtn = refs.toastHost.querySelector('.toast-close');
  closeBtn?.addEventListener('click', clearToast);
  const progress = refs.toastHost.querySelector('.toast-progress');
  if (progress) {
    progress.style.animation = 'none';
    void progress.offsetWidth;
    progress.style.animation = `toast-progress ${duration}ms linear forwards`;
  }
  state.toastTimerId = window.setTimeout(clearToast, duration);
}

function clearToast() {
  if (state.toastTimerId) {
    clearTimeout(state.toastTimerId);
    state.toastTimerId = null;
  }
  if (refs.toastHost) {
    refs.toastHost.innerHTML = '';
  }
}

function setLoginFeedback(message, type = 'status') {
  if (!refs.loginStatus) return;
  refs.loginStatus.textContent = message || '';
  if (type === 'error') {
    refs.loginStatus.classList.add('error');
  } else {
    refs.loginStatus.classList.remove('error');
  }
}

function startSessionTimer(seconds) {
  stopSessionTimer();
  const parsed = Number(seconds);
  state.sessionSecondsRemaining = Number.isFinite(parsed) ? Math.max(0, parsed) : 0;
  updateSessionProgressBars();
  if (!state.authenticated || state.sessionSecondsRemaining <= 0) {
    if (state.sessionSecondsRemaining <= 0 && state.authenticated) {
      handleSessionExpired();
    }
    return;
  }
  state.sessionTimerId = window.setInterval(() => {
    if (state.sessionSecondsRemaining <= 1) {
      stopSessionTimer();
      handleSessionExpired();
      return;
    }
    state.sessionSecondsRemaining -= 1;
    updateSessionProgressBars();
  }, 1000);
}

function stopSessionTimer() {
  if (state.sessionTimerId) {
    window.clearInterval(state.sessionTimerId);
    state.sessionTimerId = null;
  }
  state.sessionSecondsRemaining = 0;
  updateSessionProgressBars();
}

function updateSessionProgressBars() {
  const percent = Math.max(
    0,
    Math.min(1, state.sessionSecondsRemaining / SESSION_TIMEOUT_SECONDS)
  );
  const width = `${percent * 100}%`;
  if (refs.loginSessionProgress) {
    refs.loginSessionProgress.style.width = width;
  }
  if (refs.appSessionProgress) {
    refs.appSessionProgress.style.width = width;
  }
  const active = percent > 0 && state.authenticated;
  refs.loginStatusTray?.classList.toggle('active', active);
  refs.appStatusTray?.classList.toggle('active', active);
  refreshContextBars();
}

function formatTimeRemaining(seconds) {
  const safe = Math.max(0, Math.floor(seconds));
  const minutes = Math.floor(safe / 60);
  const secs = safe % 60;
  return `${minutes}:${secs.toString().padStart(2, '0')}`;
}

async function handleSessionExpired(options = {}) {
  const message = options.message || 'Session expired. Please unlock again.';
  stopSessionTimer();
  if (state.activeDialog) {
    closeDialog('session-expired');
  }
  if (!options.skipBackendLogout) {
    try {
      await invoke('logout');
    } catch (err) {
      console.error(err);
    }
  }
  state.authenticated = false;
  toggleView();
  setLoginFeedback(message, 'error');
  showToast({ type: 'error', title: 'Session expired', message });
}

async function refreshSessionTimer(options = {}) {
  try {
    const status = await invoke('session_status_detail');
    if (status.authenticated) {
      startSessionTimer(status.seconds_remaining || SESSION_TIMEOUT_SECONDS);
    } else {
      stopSessionTimer();
      if (state.authenticated && options.enforce) {
        await handleSessionExpired({ skipBackendLogout: true });
      }
    }
    return status;
  } catch (err) {
    console.error('Unable to load session status', err);
    return null;
  }
}

async function ensureSessionForEditing() {
  const status = await refreshSessionTimer({ enforce: true });
  if (!status || !status.authenticated) {
    return await promptReauth('Session expired. Please authenticate to continue.');
  }
  if ((status.seconds_remaining || 0) < SESSION_MIN_REAUTH_SECONDS) {
    return await promptReauth('Session is about to expire. Re-authenticate to edit.');
  }
  return true;
}

function promptReauth(message) {
  return new Promise((resolve) => {
    if (!refs.modalBackdrop || !refs.modalTitle || !refs.modalContent) {
      resolve(false);
      return;
    }
    const helper = message
      ? `<p class="helper-text">${escapeHtml(message)}</p>`
      : '';
    const body = `
      ${helper}
      <form id="reauth-form" class="dialog-form">
        <label>Master password
          <input type="password" id="reauth-password" autocomplete="current-password" autofocus />
        </label>
        <div class="dialog-actions">
          <button type="button" id="reauth-cancel" class="ghost-btn">Cancel</button>
          <button type="submit" id="reauth-submit" class="primary-btn">Continue</button>
        </div>
        <div id="reauth-status" class="dialog-status"></div>
      </form>
    `;
    showDialogContent('Re-authenticate', body, 'reauth');
    state.dialogCloseHandler = (kind) => {
      if (kind === 'reauth') {
        state.dialogCloseHandler = null;
        resolve(false);
      }
    };
    closeCommandMenu();
    const form = document.getElementById('reauth-form');
    const cancelBtn = document.getElementById('reauth-cancel');
    const submitBtn = document.getElementById('reauth-submit');
    const statusEl = document.getElementById('reauth-status');
    cancelBtn?.addEventListener('click', () => {
      state.dialogCloseHandler = null;
      closeDialog();
      resolve(false);
    });
    form?.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (!submitBtn) return;
      const passwordInput = document.getElementById('reauth-password');
      const password = passwordInput ? passwordInput.value.trim() : '';
      if (!password) {
        if (statusEl) statusEl.textContent = 'Password required.';
        return;
      }
      submitBtn.disabled = true;
      if (statusEl) statusEl.textContent = 'Validating...';
      try {
        await invoke('login', { password });
        await refreshSessionTimer();
        state.dialogCloseHandler = null;
        closeDialog();
        resolve(true);
      } catch (err) {
        if (statusEl) statusEl.textContent = formatError(err);
      } finally {
        submitBtn.disabled = false;
      }
    });
  });
}

function attachDialogHandlers(kind) {
  if (kind === 'settings') {
    initSyncSettingsForm();
  } else if (kind === 'sync-upload') {
    const btn = document.getElementById('sync-upload-btn');
    const statusEl = document.getElementById('sync-upload-status');
    const helperEl = document.getElementById('sync-upload-helper');
    const progressEl = document.getElementById('sync-upload-progress');
    resetDialogProgress(progressEl);
    btn?.addEventListener('click', () => handleSyncUpload(statusEl, btn, progressEl, helperEl));
    refreshSyncStatus(statusEl, {
      helperEl,
      actionButton: btn,
      requireConfigMessage: CONNECT_GOOGLE_HELPER,
    });
  } else if (kind === 'sync-import') {
    const btn = document.getElementById('sync-download-btn');
    const statusEl = document.getElementById('sync-download-status');
    const helperEl = document.getElementById('sync-import-helper');
    const progressEl = document.getElementById('sync-download-progress');
    resetDialogProgress(progressEl);
    btn?.addEventListener('click', () => handleSyncDownload(statusEl, btn, progressEl, helperEl));
    refreshSyncStatus(statusEl, {
      helperEl,
      actionButton: btn,
      requireConfigMessage: CONNECT_GOOGLE_HELPER,
    });
    loadImportBundles();
  } else if (kind === 'change-password') {
    initChangePasswordDialog();
  } else if (kind === 'about') {
    refs.modalContent?.querySelectorAll('[data-about-link]').forEach((link) => {
      link.addEventListener('click', async (event) => {
        event.preventDefault();
        await openExternalLink(link.getAttribute('href'));
      });
    });
    refs.modalContent?.querySelectorAll('[data-copy-link]').forEach((button) => {
      button.addEventListener('click', async (event) => {
        event.preventDefault();
        const link = button.getAttribute('data-copy-link');
        const label = button.getAttribute('data-copy-label') || 'Link';
        await copyLinkToClipboard(link, label);
      });
    });
  }
}

function updateSyncConnectionState(connected) {
  const connectionState = document.getElementById('sync-connection-state');
  if (!connectionState) return;
  connectionState.textContent = connected ? 'Google Drive linked' : 'Not connected';
  connectionState.classList.toggle('connected', connected);
  connectionState.classList.toggle('disconnected', !connected);
}

function handleOAuthDeepLinkResult(payload = {}) {
  const oauthStatus = document.getElementById('oauth-status');
  if (!oauthStatus) return;
  const message = payload.message || (payload.success ? 'OAuth complete. Refresh token stored.' : 'OAuth failed.');
  if (payload.success) {
    oauthStatus.textContent = message;
    const oauthInput = document.getElementById('oauth-code-input');
    if (oauthInput) {
      oauthInput.value = '';
    }
    state.oauthState = null;
    updateSyncConnectionState(true);
    const connectionMessage = document.getElementById('sync-connection-message');
    if (connectionMessage) {
      connectionMessage.textContent = 'Refresh token stored securely in your vault.';
    }
    const summaryTargets = getSyncSummaryTargets();
    if (summaryTargets) {
      refreshSyncStatus(null, { summaryTargets });
    }
    showToast({ type: 'success', title: 'Google connected', message });
  } else {
    oauthStatus.textContent = `OAuth failed: ${message}`;
    showToast({ type: 'error', title: 'OAuth failed', message });
  }
}

function registerOAuthDeepLinkListener() {
  const eventApi = window.__TAURI__?.event;
  if (!eventApi || typeof eventApi.listen !== 'function') return;
  eventApi.listen('sync://oauth-complete', (event) => {
    handleOAuthDeepLinkResult(event?.payload || {});
  });
}

async function initSyncSettingsForm() {
  const summaryTargets = getSyncSummaryTargets();
  const connectionMessage = document.getElementById('sync-connection-message');
  const prefUpload = document.getElementById('pref-auto-upload');
  const prefDownload = document.getElementById('pref-auto-download');
  const prefKeep = document.getElementById('pref-keep-revisions');
  const prefStatus = document.getElementById('preferences-status');
  const prefBtn = document.getElementById('save-preferences-btn');
  const oauthBtn = document.getElementById('begin-oauth-btn');
  const completeOauthBtn = document.getElementById('complete-oauth-btn');
  const oauthInput = document.getElementById('oauth-code-input');
  const oauthStatus = document.getElementById('oauth-status');
  const manualForm = document.getElementById('manual-refresh-form');
  const manualInput = document.getElementById('manual-refresh-token');
  const manualStatus = document.getElementById('manual-refresh-status');
  const manualWrapper = document.getElementById('manual-config');
  const manualToggle = document.getElementById('manual-config-toggle');
  const manualPanel = document.getElementById('manual-config-panel');
  if (summaryTargets) {
    refreshSyncStatus(null, { summaryTargets });
  }
  try {
    const snapshot = await invoke('sync_config_snapshot_command');
    updateSyncConnectionState(Boolean(snapshot.refresh_token_present));
    if (connectionMessage) {
      connectionMessage.textContent = snapshot.refresh_token_present
        ? 'Refresh token stored securely in your vault.'
        : 'Connect Google Drive to start syncing across devices.';
    }
    if (manualInput && snapshot.refresh_token_present) {
      manualInput.placeholder = 'Paste to replace the stored refresh token';
    }
  } catch (err) {
    if (connectionMessage) {
      connectionMessage.textContent = `Error loading sync config: ${formatError(err)}`;
    }
  }
  try {
    const prefs = await invoke('sync_preferences_command');
    prefUpload.checked = prefs.auto_upload_on_exit;
    prefDownload.checked = prefs.auto_download_on_new;
    prefKeep.value = prefs.keep_revisions || 5;
  } catch (err) {
    prefStatus.textContent = `Unable to load preferences: ${formatError(err)}`;
  }
  const setManualConfigExpanded = (expanded) => {
    manualPanel?.classList.toggle('hidden', !expanded);
    manualWrapper?.classList.toggle('expanded', expanded);
    if (manualToggle) {
      manualToggle.setAttribute('aria-expanded', expanded ? 'true' : 'false');
    }
  };
  setManualConfigExpanded(false);
  manualToggle?.addEventListener('click', () => {
    const expanded = manualToggle.getAttribute('aria-expanded') === 'true';
    setManualConfigExpanded(!expanded);
  });
  prefBtn?.addEventListener('click', async () => {
    prefStatus.textContent = 'Saving preferences...';
    try {
      await invoke('update_sync_preferences_command', {
        auto_upload_on_exit: prefUpload.checked,
        auto_download_on_new: prefDownload.checked,
        keep_revisions: Number(prefKeep.value) || 5,
      });
      prefStatus.textContent = 'Preferences saved.';
      showToast({ type: 'success', title: 'Preferences saved' });
    } catch (err) {
      prefStatus.textContent = `Save failed: ${formatError(err)}`;
    }
  });
  manualForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const refreshToken = manualInput.value.trim();
    if (!refreshToken) {
      manualStatus.textContent = 'Enter a refresh token.';
      return;
    }
    manualStatus.textContent = 'Saving refresh token...';
    try {
      await invoke('configure_sync', { refreshToken });
      manualStatus.textContent = 'Stored refresh token.';
      manualInput.value = '';
      updateSyncConnectionState(true);
      if (summaryTargets) {
        refreshSyncStatus(null, { summaryTargets });
      }
      showToast({ type: 'success', title: 'Sync updated', message: 'Refresh token saved.' });
    } catch (err) {
      manualStatus.textContent = `Save failed: ${formatError(err)}`;
    }
  });
  oauthBtn?.addEventListener('click', async () => {
    oauthStatus.textContent = 'Generating authorization link...';
    try {
      const begin = await invoke('begin_sync_oauth_command');
      state.oauthState = begin.state;
      const shellApi = window.__TAURI__?.shell;
      if (shellApi && typeof shellApi.open === 'function') {
        await shellApi.open(begin.auth_url);
      } else {
        window.open(begin.auth_url, '_blank');
      }
      const link = document.createElement('a');
      link.href = begin.auth_url;
      link.target = '_blank';
      link.rel = 'noreferrer';
      link.textContent = 'Open the authorization link again';
      const codeBlock = document.createElement('code');
      codeBlock.style.wordBreak = 'break-all';
      codeBlock.style.display = 'block';
      codeBlock.textContent = begin.auth_url;
      oauthStatus.innerHTML = '';
      oauthStatus.append(
        'Browser opened. Complete the Google prompt — if nothing happened, ',
        link,
        '. You can also copy this URL:',
        document.createElement('br'),
        codeBlock,
      );
    } catch (err) {
      oauthStatus.textContent = `OAuth init failed: ${formatError(err)}`;
    }
  });
  completeOauthBtn?.addEventListener('click', async () => {
    if (!state.oauthState) {
      oauthStatus.textContent = 'Start the OAuth flow first.';
      return;
    }
    const code = oauthInput.value.trim();
    if (!code) {
      oauthStatus.textContent = 'Enter the authorization code.';
      return;
    }
    oauthStatus.textContent = 'Exchanging code...';
    try {
      await invoke('complete_sync_oauth_command', {
        state_token: state.oauthState,
        auth_code: code,
      });
      oauthStatus.textContent = 'OAuth complete. Refresh token stored.';
      showToast({ type: 'success', title: 'Google connected' });
      state.oauthState = null;
      oauthInput.value = '';
      updateSyncConnectionState(true);
      if (summaryTargets) {
        refreshSyncStatus(null, { summaryTargets });
      }
    } catch (err) {
      oauthStatus.textContent = `OAuth failed: ${formatError(err)}`;
    }
  });
}

async function refreshSyncStatus(statusEl, options = {}) {
  const { helperEl, actionButton, requireConfigMessage, summaryTargets } = options;
  const hasSummaryTargets = Boolean(summaryTargets?.revisionEl || summaryTargets?.uploadEl);
  if (!statusEl && !hasSummaryTargets) {
    return;
  }
  try {
    const status = await invoke('sync_status_command');
    state.syncConfigured = !!status.configured;
    if (hasSummaryTargets) {
      updateSyncSummary(summaryTargets, status);
    } else if (statusEl) {
      const last = status.last_uploaded_at || 'never';
      statusEl.textContent = `Last revision: ${status.last_revision} • Last upload: ${last}`;
    }
    updateSyncDialogHelper(helperEl, actionButton, requireConfigMessage);
  } catch (err) {
    const errorText = `Unable to load status: ${formatError(err)}`;
    if (hasSummaryTargets) {
      updateSyncSummary(summaryTargets, null, errorText);
    } else if (statusEl) {
      statusEl.textContent = errorText;
    }
    state.syncConfigured = false;
    updateSyncDialogHelper(helperEl, actionButton, requireConfigMessage);
  }
}

function updateSyncDialogHelper(helperEl, actionButton, requireConfigMessage) {
  const message = requireConfigMessage || CONNECT_GOOGLE_HELPER;
  if (!helperEl && !actionButton) {
    return;
  }
  if (!state.syncConfigured) {
    if (helperEl) {
      helperEl.textContent = message;
      helperEl.classList.add('warning');
    }
    if (actionButton && actionButton.dataset.loading !== 'true') {
      actionButton.disabled = true;
    }
  } else {
    if (helperEl) {
      helperEl.textContent = '';
      helperEl.classList.remove('warning');
    }
    if (actionButton && actionButton.dataset.loading !== 'true') {
      actionButton.disabled = false;
    }
  }
}

function updateSyncSummary(targets, status, errorMessage) {
  const revisionEl = targets?.revisionEl;
  const uploadEl = targets?.uploadEl;
  if (!revisionEl && !uploadEl) {
    return;
  }
  if (errorMessage) {
    if (revisionEl) {
      revisionEl.textContent = '--';
      revisionEl.title = '';
    }
    if (uploadEl) {
      uploadEl.textContent = errorMessage;
      uploadEl.title = '';
    }
    return;
  }
  if (revisionEl) {
    revisionEl.textContent = `${status?.last_revision ?? '--'}`;
    revisionEl.title = '';
  }
  if (uploadEl) {
    if (status?.last_uploaded_at) {
      const { short, tooltip } = formatFriendlyTimestamp(status.last_uploaded_at);
      uploadEl.textContent = short;
      uploadEl.title = tooltip;
    } else {
      uploadEl.textContent = 'Never';
      uploadEl.title = '';
    }
  }
}


function getSyncSummaryTargets() {
  const revisionEl = document.getElementById('sync-status-revision');
  const uploadEl = document.getElementById('sync-status-upload');
  if (!revisionEl && !uploadEl) {
    return null;
  }
  return { revisionEl, uploadEl };
}

function resetDialogProgress(progressEl) {
  stopDialogProgressTimer();
  stopDialogProgressHideTimer();
  if (!progressEl) return;
  progressEl.style.width = '0%';
  const container = progressEl.parentElement;
  container?.classList.remove('visible');
}

function startDialogProgress(progressEl) {
  stopDialogProgressTimer();
  stopDialogProgressHideTimer();
  if (!progressEl) return;
  const container = progressEl.parentElement;
  if (container) {
    container.classList.add('visible');
  }
  progressEl.style.width = '2%';
  let progress = 2;
  dialogProgressTimerId = window.setInterval(() => {
    progress = Math.min(progress + Math.random() * 15 + 5, 90);
    progressEl.style.width = `${progress}%`;
    if (progress >= 90) {
      stopDialogProgressTimer();
    }
  }, 400);
}

function finishDialogProgress(progressEl) {
  stopDialogProgressTimer();
  stopDialogProgressHideTimer();
  if (!progressEl) return;
  const container = progressEl.parentElement;
  if (container) {
    container.classList.add('visible');
  }
  progressEl.style.width = '100%';
  dialogProgressHideTimeoutId = window.setTimeout(() => {
    if (container) {
      container.classList.remove('visible');
    }
    progressEl.style.width = '0%';
    dialogProgressHideTimeoutId = null;
  }, 1200);
}

function stopDialogProgressTimer() {
  if (dialogProgressTimerId) {
    window.clearInterval(dialogProgressTimerId);
    dialogProgressTimerId = null;
  }
}

function stopDialogProgressHideTimer() {
  if (dialogProgressHideTimeoutId) {
    window.clearTimeout(dialogProgressHideTimeoutId);
    dialogProgressHideTimeoutId = null;
  }
}

async function loadImportBundles() {
  const host = document.getElementById('import-list');
  if (!host) return;
  host.innerHTML = '<p>Loading bundles...</p>';
  try {
    const bundles = await invoke('list_drive_bundles_command');
    state.importBundles = bundles;
    if (!state.selectedBundleId && bundles.length > 0) {
      state.selectedBundleId = bundles[0].file_id;
    }
    renderImportBundles();
  } catch (err) {
    state.importBundles = [];
    state.selectedBundleId = null;
    const message = formatError(err);
    if (/not authenticated/i.test(message)) {
      host.innerHTML = `<p class="error-text">${escapeHtml(CONNECT_GOOGLE_HELPER)}</p>`;
    } else {
      host.innerHTML = `<p class="error-text">${escapeHtml(message)}</p>`;
    }
  }
}

function renderImportBundles() {
  const host = document.getElementById('import-list');
  const btn = document.getElementById('sync-download-btn');
  if (!host) return;
  if (!state.importBundles.length) {
    host.innerHTML = '<p>No bundles found. Create one from another device.</p>';
    btn && (btn.disabled = true);
    return;
  }
  const rows = state.importBundles
    .map((bundle) => {
      const checked = bundle.file_id === state.selectedBundleId;
      const label = bundle.profile ? `${bundle.profile} rev ${bundle.revision ?? '?'}` : bundle.name;
      const time = bundle.modified_time || 'unknown';
      return `
        <label class="import-row">
          <input type="radio" name="bundle" value="${bundle.file_id}" ${checked ? 'checked' : ''} />
          <div class="import-info">
            <div class="import-name">${escapeHtml(label)}</div>
            <div class="import-meta">${escapeHtml(time)}</div>
          </div>
        </label>
      `;
    })
    .join('');
  host.innerHTML = rows;
  host.querySelectorAll('input[type="radio"]').forEach((input) => {
    input.addEventListener('change', (event) => {
      state.selectedBundleId = event.target.value;
      if (btn) btn.disabled = !state.selectedBundleId || !state.syncConfigured;
    });
  });
  if (btn) btn.disabled = !state.selectedBundleId || !state.syncConfigured;
}

async function handleSyncUpload(statusEl, button, progressEl, helperEl) {
  if (!button) return;
  if (!state.syncConfigured) {
    if (statusEl) {
      statusEl.textContent = CONNECT_GOOGLE_HELPER;
    }
    if (helperEl) {
      helperEl.textContent = CONNECT_GOOGLE_HELPER;
      helperEl.classList.add('warning');
    }
    showToast({
      type: 'warning',
      title: 'Connect Google Drive',
      message: 'Open Settings and link Google Drive before syncing.',
    });
    return;
  }
  button.disabled = true;
  button.dataset.loading = 'true';
  if (statusEl) {
    statusEl.textContent = 'Uploading encrypted bundle...';
  }
  startDialogProgress(progressEl);
  try {
    await invoke('sync_upload_command');
    if (statusEl) {
      statusEl.textContent = 'Upload complete.';
    }
    showToast({ type: 'success', title: 'Sync complete', message: 'Bundle uploaded to Drive.' });
  } catch (err) {
    const message = formatError(err);
    if (statusEl) {
      statusEl.textContent = `Upload failed: ${message}`;
    }
    if (message.includes('SYNC_NOT_CONFIGURED')) {
      showToast({
        type: 'error',
        title: 'Connect Google Drive',
        message: 'Open Settings → Sync to link Google Drive before syncing.',
      });
      openDialog('settings');
    } else {
      showToast({ type: 'error', title: 'Sync failed', message });
    }
  } finally {
    button.disabled = false;
    delete button.dataset.loading;
    finishDialogProgress(progressEl);
    refreshSyncStatus(statusEl, {
      helperEl,
      actionButton: button,
      requireConfigMessage: CONNECT_GOOGLE_HELPER,
    });
  }
}

async function handleSyncDownload(statusEl, button, progressEl, helperEl) {
  if (!button) return;
  if (!state.syncConfigured) {
    statusEl.textContent = CONNECT_GOOGLE_HELPER;
    if (helperEl) {
      helperEl.textContent = CONNECT_GOOGLE_HELPER;
      helperEl.classList.add('warning');
    }
    showToast({
      type: 'warning',
      title: 'Connect Google Drive',
      message: 'Open Settings and link Google Drive before importing.',
    });
    return;
  }
  button.disabled = true;
  button.dataset.loading = 'true';
  statusEl.textContent = 'Downloading latest bundle...';
  startDialogProgress(progressEl);
  try {
    if (state.selectedBundleId) {
      await invoke('sync_download_specific_command', { fileId: state.selectedBundleId });
    } else {
      await invoke('sync_download_command');
    }
    statusEl.textContent = 'Import complete. Reloading vault...';
    showToast({ type: 'success', title: 'Import complete', message: 'Bundle restored locally.' });
    await fetchSnapshot();
  } catch (err) {
    const message = formatError(err);
    statusEl.textContent = `Import failed: ${message}`;
    showToast({ type: 'error', title: 'Import failed', message });
  } finally {
    button.disabled = false;
    delete button.dataset.loading;
    finishDialogProgress(progressEl);
    refreshSyncStatus(statusEl, {
      helperEl,
      actionButton: button,
      requireConfigMessage: CONNECT_GOOGLE_HELPER,
    });
  }
}

function initChangePasswordDialog() {
  const form = document.getElementById('change-password-form');
  const statusEl = document.getElementById('change-password-status');
  const submitBtn = document.getElementById('change-password-submit');
  const cancelBtn = document.getElementById('change-password-cancel');
  cancelBtn?.addEventListener('click', () => closeDialog());
  form?.addEventListener('submit', (event) => handleChangePasswordSubmit(event, statusEl, submitBtn));
}

async function handleChangePasswordSubmit(event, statusEl, submitBtn) {
  event.preventDefault();
  const currentInput = document.getElementById('change-password-current');
  const newInput = document.getElementById('change-password-new');
  const confirmInput = document.getElementById('change-password-confirm');
  if (!currentInput || !newInput || !confirmInput || !statusEl) return;
  const current = currentInput.value.trim();
  const next = newInput.value.trim();
  const confirm = confirmInput.value.trim();
  if (!current || !next || !confirm) {
    statusEl.textContent = 'All fields are required.';
    return;
  }
  if (next !== confirm) {
    statusEl.textContent = 'New passwords do not match.';
    return;
  }
  statusEl.textContent = 'Updating password...';
  if (submitBtn) {
    submitBtn.disabled = true;
  }
  try {
    await invoke('change_password', {
      currentPassword: current,
      newPassword: next,
      confirmPassword: confirm,
    });
    await refreshSessionTimer();
    currentInput.value = '';
    newInput.value = '';
    confirmInput.value = '';
    statusEl.textContent = 'Password updated successfully.';
    showToast({ type: 'success', title: 'Password changed', message: 'Vault password updated.' });
    window.setTimeout(() => {
      closeDialog();
    }, 600);
  } catch (err) {
    statusEl.textContent = formatError(err);
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
    }
  }
}

function setupMenuHandlers() {
  if (!refs.menuButton || !refs.menuDropdown) return;
  refs.menuButton.addEventListener('click', (event) => {
    event.stopPropagation();
    toggleCommandMenu();
  });
  document.addEventListener('click', (event) => {
    if (!refs.menuDropdown || !refs.menuButton) return;
    if (
      refs.menuDropdown.contains(event.target) ||
      refs.menuButton.contains(event.target)
    ) {
      return;
    }
    closeCommandMenu();
  });
  refs.menuDropdown.querySelectorAll('[data-dialog]').forEach((btn) => {
    btn.addEventListener('click', async (event) => {
      event.preventDefault();
      const kind = event.currentTarget.getAttribute('data-dialog');
      if (!kind) return;
      if (dialogRequiresAuthentication(kind)) {
        const ready = await ensureSessionForEditing();
        if (!ready) {
          return;
        }
      }
      openDialog(kind);
    });
  });
  [refs.modalClose, refs.modalDismiss].forEach((btn) => {
    btn?.addEventListener('click', closeDialog);
  });
  refs.modalBackdrop?.addEventListener('click', (event) => {
    if (event.target === refs.modalBackdrop) {
      closeDialog();
    }
  });
}

function toggleCommandMenu() {
  if (state.menuOpen) {
    closeCommandMenu();
  } else {
    openCommandMenu();
  }
}

function dialogRequiresAuthentication(kind) {
  return AUTH_REQUIRED_DIALOGS.has(kind);
}

function openCommandMenu() {
  if (!refs.menuDropdown || !refs.menuButton) return;
  refs.menuDropdown.classList.remove('hidden');
  state.menuOpen = true;
  refs.menuButton.setAttribute('aria-expanded', 'true');
}

function closeCommandMenu() {
  if (!refs.menuDropdown || !refs.menuButton) return;
  refs.menuDropdown.classList.add('hidden');
  state.menuOpen = false;
  refs.menuButton.setAttribute('aria-expanded', 'false');
}

function openDialog(kind) {
  if (!kind) return;
  const { title, body } = getDialogContent(kind);
  showDialogContent(title, body, kind);
  closeCommandMenu();
  attachDialogHandlers(kind);
}

function showDialogContent(title, body, kind = null) {
  if (!refs.modalBackdrop || !refs.modalTitle || !refs.modalContent) return;
  refs.modalTitle.textContent = title;
  refs.modalContent.innerHTML = body;
  const profileBadge = document.getElementById('dialog-profile-pill');
  if (profileBadge) {
    const profile = state.vaultContext?.profile || 'default';
    profileBadge.textContent = `Profile: ${profile}`;
    profileBadge.title = `Profile: ${profile}`;
  }
  refs.modalBackdrop.classList.remove('hidden');
  state.activeDialog = kind;
  state.dialogCloseHandler = null;
}

function closeDialog(reason) {
  if (!refs.modalBackdrop) return;
  refs.modalBackdrop.classList.add('hidden');
  const handler = state.dialogCloseHandler;
  const kind = state.activeDialog;
  state.activeDialog = null;
  state.dialogCloseHandler = null;
  if (typeof handler === 'function') {
    handler(kind, reason);
  }
}

function getDialogContent(kind) {
  switch (kind) {
    case 'settings':
      return {
        title: 'Settings',
        body: `
          <div class="settings-grid">
            <section class="settings-card">
              <h3>Vault Sync Status</h3>
              <p class="helper-text">Keep an eye on the latest uploaded revision.</p>
              <div id="sync-status-summary" class="status-pill-group">
                <div class="status-pill status-pill-line">
                  <span class="pill-label">Last Revision:</span>
                  <span id="sync-status-revision" class="pill-value">--</span>
                </div>
                <div class="status-pill status-pill-line">
                  <span class="pill-label">Uploaded at:</span>
                  <span id="sync-status-upload" class="pill-value">Loading...</span>
                </div>
              </div>
            </section>
            <section class="settings-card">
              <h3>Auto Sync</h3>
              <label class="switch">
                <input type="checkbox" id="pref-auto-upload" />
                <span>Upload on exit</span>
              </label>
              <label class="switch">
                <input type="checkbox" id="pref-auto-download" />
                <span>Auto-download newer bundle</span>
              </label>
              <label>Keep last N revisions
                <input type="number" id="pref-keep-revisions" min="1" max="50" value="5" />
              </label>
              <button id="save-preferences-btn" class="ghost-btn">Save Preferences</button>
              <div id="preferences-status" class="dialog-status"></div>
            </section>
            <section class="settings-card full-width">
              <h3>Google Drive Connection</h3>
              <p class="helper-text">FerrumVault bundles the Google OAuth client, so you only authorize once.</p>
              <div id="sync-connection-state" class="connection-pill disconnected">Not connected</div>
              <div id="sync-connection-message" class="dialog-status"></div>
              <button id="begin-oauth-btn" class="primary-btn">Connect with Google</button>
              <div class="manual-config">
                <button id="manual-config-toggle" class="manual-config-toggle" type="button" aria-expanded="false">
                  <span>Manually configure Google account</span>
                  <span class="chevron" aria-hidden="true">▼</span>
                </button>
                <p class="helper-text">Only use these fields if support asked you to paste codes manually.</p>
                <div id="manual-config-panel" class="manual-config-panel hidden">
                  <div class="manual-section">
                    <h4>Paste authorization code</h4>
                    <p class="helper-text">Paste the code you copied from your browser.</p>
                    <label>Authorization code
                      <input type="text" id="oauth-code-input" placeholder="Paste code from browser" />
                    </label>
                    <button id="complete-oauth-btn" class="ghost-btn">Submit Code</button>
                    <div id="oauth-status" class="dialog-status"></div>
                  </div>
                  <div class="settings-divider"></div>
                  <div class="manual-section">
                    <h4>Manual refresh token</h4>
                    <p class="helper-text">Paste an existing refresh token if support provided one.</p>
                    <form id="manual-refresh-form" class="dialog-form compact">
                      <label>Refresh token
                        <textarea id="manual-refresh-token" rows="2" placeholder="Paste to replace the stored refresh token"></textarea>
                      </label>
                      <button type="submit" class="ghost-btn">Store Refresh Token</button>
                      <div id="manual-refresh-status" class="dialog-status"></div>
                    </form>
                  </div>
                </div>
              </div>
            </section>
          </div>
        `,
      };
    case 'sync-upload':
      return {
        title: 'Sync to Google Drive',
        body: `
          <p>Encrypts the current vault with the Master Encryption Key and uploads the protected bundle to the FerrumVault folder in Google Drive.</p>
          <div id="sync-upload-helper" class="dialog-helper"></div>
          <div id="sync-upload-status" class="dialog-status"></div>
          <button id="sync-upload-btn" class="primary-btn">Upload now</button>
          <div id="sync-upload-progress-bar" class="dialog-progress-line">
            <div id="sync-upload-progress" class="dialog-progress-fill"></div>
          </div>
        `,
      };
    case 'sync-import':
      return {
        title: 'Import from Google Drive',
        body: `
          <p>Select a bundle to restore on this device.</p>
          <div id="sync-import-helper" class="dialog-helper"></div>
          <div id="import-list"></div>
          <div id="sync-download-status" class="dialog-status"></div>
          <button id="sync-download-btn" class="primary-btn" disabled>Download selected bundle</button>
          <div id="sync-download-progress-bar" class="dialog-progress-line">
            <div id="sync-download-progress" class="dialog-progress-fill"></div>
          </div>
        `,
      };
    case 'change-password':
      return {
        title: 'Change Vault Password',
        body: `
          <form id="change-password-form" class="dialog-form">
            <label>Current password
              <input type="password" id="change-password-current" autocomplete="current-password" />
            </label>
            <label>New password
              <input type="password" id="change-password-new" autocomplete="new-password" />
            </label>
            <label>Confirm new password
              <input type="password" id="change-password-confirm" autocomplete="new-password" />
            </label>
            <div class="dialog-actions">
              <button type="button" class="ghost-btn" id="change-password-cancel">Cancel</button>
              <button type="submit" class="primary-btn" id="change-password-submit">Update Password</button>
            </div>
            <div id="change-password-status" class="dialog-status"></div>
          </form>
        `,
      };
    case 'about': {
      const appName = escapeHtml(state.appInfo?.name || APP_DISPLAY_NAME);
      const version = state.appInfo?.version ? escapeHtml(state.appInfo.version) : 'Unavailable';
      const githubDisplay = escapeHtml(formatDisplayUrl(APP_REPO_URL));
      return {
        title: 'About FerrumVault',
        body: `
          <div class="about-dialog">
            <div class="about-meta">
              <div class="about-row">
                <span class="about-label">App Name:</span>
                <span class="about-value">${appName}</span>
              </div>
              <div class="about-row">
                <span class="about-label">App Version:</span>
                <span class="about-value"><strong>${version}</strong></span>
              </div>
            </div>
            <div class="about-links-card">
              <div class="about-link-row">
                <span class="about-label">GitHub Page:</span>
                <a
                  href="${APP_REPO_URL}"
                  class="about-link-text"
                  data-about-link="repo"
                  title="${escapeAttr(APP_REPO_URL)}"
                >${githubDisplay}</a>
                <button
                  type="button"
                  class="about-copy-btn"
                  data-copy-link="${escapeAttr(APP_REPO_URL)}"
                  data-copy-label="GitHub Page"
                  title="Copy GitHub link"
                >📋</button>
              </div>
              <div class="about-link-row">
                <span class="about-label">User Guide:</span>
                <a
                  href="${USER_GUIDE_URL}"
                  class="about-link-text"
                  data-about-link="docs"
                  title="${escapeAttr(USER_GUIDE_URL)}"
                >user-guide.md</a>
                <button
                  type="button"
                  class="about-copy-btn"
                  data-copy-link="${escapeAttr(USER_GUIDE_URL)}"
                  data-copy-label="User Guide"
                  title="Copy User Guide link"
                >📋</button>
              </div>
            </div>
          </div>
        `,
      };
    }
    default:
      return {
        title: 'FerrumVault',
        body: '<p>Feature coming soon.</p>',
      };
  }
}

function render() {
  renderFolders();
  renderTags();
  renderCredentials();
  renderDetail();
  renderBreadcrumb();
}

function renderBreadcrumb() {
  if (!refs.breadcrumb) return;
  const parts = [];
  parts.push(state.folderFilter || "All Folders");
  if (state.tagFilter) {
    parts.push(`#${state.tagFilter}`);
  }
  if (state.searchText) {
    parts.push(`“${state.searchText}”`);
  }
  refs.breadcrumb.textContent = parts.join(" / ");
}


function renderFolders() {
  if (!state.snapshot) return;
  refs.folderList.innerHTML = "";
  const stats = computeFilteredStats();
  const total = state.snapshot.folders.reduce((sum, f) => sum + f.count, 0);
  const allLabel = formatCountLabel("All Folders", stats.totalFiltered, total);
  addFolderButton(allLabel, null);
  state.snapshot.folders.forEach((folder) => {
    const filtered = stats.folders[folder.name] || 0;
    const label = formatCountLabel(folder.name, filtered, folder.count);
    addFolderButton(label, folder.name);
  });
}

function addFolderButton(label, value) {
  const btn = document.createElement("button");
  btn.innerHTML = label;
  if (value === state.folderFilter || (value === null && !state.folderFilter)) {
    btn.classList.add("active");
  }
  btn.addEventListener("click", () => {
    state.folderFilter = value;
    fetchSnapshot();
  });
  btn.addEventListener('dragover', (event) => event.preventDefault());
  btn.addEventListener('drop', (event) => handleFolderDrop(event, value));
  refs.folderList.appendChild(btn);
}

function renderTags() {
  if (!state.snapshot) return;
  refs.tagList.innerHTML = "";
  const stats = computeFilteredStats();
  const totalTags = state.snapshot.tags.length;
  addTagButton(renderTagLabel('All Tags', totalTags, stats.totalFiltered), null);
  state.snapshot.tags.forEach((tag) => {
    const filtered = stats.tags[tag.name] || 0;
    const label = renderTagLabel(tag.name, tag.count, filtered);
    addTagButton(label, tag.name);
  });
}

function renderTagLabel(name, totalCount, filteredCount) {
  const filterPart = (state.searchText || state.folderFilter || state.tagFilter)
    ? `<span class=\"tag-metric\">🔎 ${filteredCount}</span>`
    : `<span class=\"tag-metric\">🔎 ${totalCount}</span>`;
  return `<span class=\"tag-label\"><span>${escapeHtml(name)}</span><span class=\"tag-metrics\"><span class=\"tag-metric\">🏷️ ${totalCount}</span>${filterPart}</span></span>`;
}

function formatCountLabel(name, filtered, total, opts = {}) {
  if (opts.tagOnly) {
    const count = typeof opts.assignmentCount === 'number' ? opts.assignmentCount : total;
    return `${name} (${count})`;
  }
  if (filtered && filtered !== total) {
    return `${name} (${filtered} of ${total})`;
  }
  if (!filtered && (state.searchText || state.tagFilter || state.folderFilter)) {
    return `${name} (0 of ${total})`;
  }
  return `${name} (${total})`;
}

function addTagButton(label, value) {
  const btn = document.createElement("button");
  btn.innerHTML = label;
  if (value === state.tagFilter || (value === null && !state.tagFilter)) {
    btn.classList.add("active");
  }
  btn.addEventListener("click", () => {
    state.tagFilter = value;
    fetchSnapshot();
  });
  refs.tagList.appendChild(btn);
}

async function handleFolderDrop(event, folderValue) {
  event.preventDefault();
  const data = event.dataTransfer.getData('text/plain');
  const credId = Number(data);
  if (!credId || credId === -1) return;
  try {
    const detail = await invoke('load_credential_detail', { credId });
    const payload = {
      cred_id: detail.cred_id,
      app_name: detail.app_name,
      username: detail.username || '',
      url: detail.url,
      description: detail.description,
      folder: folderValue || 'general',
      tags: detail.tags || [],
      categories: detail.categories || [],
      password: null,
    };
    await invoke('update_credential_detail', { payload });
    await fetchSnapshot();
  } catch (err) {
    console.error('Unable to move credential', err);
  }
}

function renderCredentials() {
  if (!state.snapshot) return;
  refs.credentialList.innerHTML = "";
  if (state.snapshot.credentials.length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = "No credentials match your filters.";
    refs.credentialList.appendChild(empty);
    return;
  }
  state.snapshot.credentials.forEach((cred) => {
    const card = document.createElement("button");
    card.className = "credential-card";
    if (state.selectedCredentialId === cred.cred_id) {
      card.classList.add("active");
    }
    const folder = cred.folder || "General";
    card.title = cred.tags && cred.tags.length ? `Tags: ${cred.tags.join(', ')}` : folder;
    card.draggable = true;
    card.addEventListener('dragstart', (event) => {
      event.dataTransfer.setData('text/plain', String(cred.cred_id));
    });
    card.innerHTML = `
      <div class="credential-card-header">
        <div class="credential-app-name">${escapeHtml(cred.app_name)}</div>
      </div>
      <div class="credential-card-meta">
        <span class="credential-folder-pill">📂 ${escapeHtml(folder)}</span>
      </div>
    `;
    card.addEventListener("click", () => loadCredentialDetail(cred.cred_id));
    refs.credentialList.appendChild(card);
  });
}


async function loadCredentialDetail(credId) {
  try {
    const detail = await invoke("load_credential_detail", { credId });
    if (state.snapshot) {
      state.snapshot.selected = detail;
    } else {
      state.snapshot = { selected: detail };
    }
    resetDetailState();
    state.selectedCredentialId = credId;
    await loadPasswordHistory(credId);
    renderDetail();
    renderCredentials();
  } catch (err) {
    if (String(err).includes("NOT_AUTHENTICATED")) {
      state.authenticated = false;
      toggleView();
    }
    console.error(err);
  }
}

async function loadPasswordHistory(credId) {
  try {
    const entries = await invoke('list_password_history', { credId });
    const sortedEntries = [...entries].sort((a, b) => {
      const left = Date.parse(a.changed_at_utc || '');
      const right = Date.parse(b.changed_at_utc || '');
      const leftInvalid = Number.isNaN(left);
      const rightInvalid = Number.isNaN(right);
      if (leftInvalid && rightInvalid) return 0;
      if (leftInvalid) return 1;
      if (rightInvalid) return -1;
      return right - left;
    });
    state.historyEntries = sortedEntries;
    state.historySecrets = {};
    state.historyReveal = false;
    stopHistoryTimer();
    state.historyCountdown = 0;
  } catch (err) {
    console.error('Unable to load history', err);
    state.historyEntries = [];
    state.historyReveal = false;
    stopHistoryTimer();
    state.historyCountdown = 0;
  }
}

function renderDetail() {
  if (!state.snapshot) return;
  const detail = state.snapshot.selected;
  if (!detail) {
    refs.detailPane.innerHTML = '<div class="empty-state">Select a credential to view details.</div>';
    return;
  }
  const preserveScroll = refs.detailPane.scrollTop;
  if (state.historyView) {
    refs.detailPane.innerHTML = renderHistoryPane(detail);
    bindHistoryControls();
    refs.detailPane.scrollTop = preserveScroll;
    return;
  }
  const sectionBlocks = state.editMode
    ? renderEditableSections(detail)
    : renderReadonlySections(detail);
  const hero = renderDetailHero(detail);
  const actionButtons = state.editMode
    ? `
        <button id="detail-save-btn" type="button" class="primary">Save</button>
        <button id="detail-cancel-btn" type="button" class="ghost-btn">Cancel</button>
      `
    : '<button id="detail-edit-btn" type="button" class="primary">Edit</button>';
  const passwordButtonLabel = state.editMode
    ? state.passwordEditing
      ? "Hide Password"
      : "Edit Password"
    : state.revealedPassword
    ? "Hide Password"
    : "Reveal Password";
  const passwordSection = renderPasswordSection(detail);
  const timelineSections = renderTimelineSections(detail);
  const tagCluster = renderDetailTags(detail);
  const historyCallout = renderHistoryCallout();
  const contentParts = [sectionBlocks[0], sectionBlocks[1], passwordSection];
  if (!state.editMode) {
    contentParts.push(tagCluster);
  }
  contentParts.push(...sectionBlocks.slice(2), ...timelineSections);
  contentParts.push(historyCallout);
  const orderedContent = contentParts.join('');
  refs.detailPane.innerHTML = `
    ${hero}
    <div class="detail-actions-sticky">
      <div class="detail-actions-stack">
        ${actionButtons}
        <button id="detail-password-btn" type="button" class="ghost-btn">${passwordButtonLabel}</button>
      </div>
    </div>
    <div class="detail-body">${orderedContent}</div>
  `;
  bindDetailActions(detail);
  bindPasswordFieldControls(detail);
  if (state.editMode) {
    bindEditInputs();
  }
  bindCopyButtons();
  refs.detailPane.scrollTop = preserveScroll;
  bindHistoryControls();
}

function renderDetailHero(detail) {
  return '';
}

function renderReadonlySections(detail) {
  const description = detail.description ? formatMultiline(detail.description) : '-';
  const url = detail.url ? `<a href="${detail.url}" target="_blank">${escapeHtml(detail.url)}</a>` : '-';
  const categories = detail.categories.length
    ? detail.categories.map(renderCategoryPill).join('')
    : '(none yet)';
  return [
    renderStaticSection('App Name', escapeHtml(detail.app_name), { icon: '🗂️' }),
    renderStaticSection('Username', detail.username ? escapeHtml(detail.username) : '(none)', {
      icon: '👤',
      copy: detail.username || '',
      copyLabel: 'username',
    }),
    renderStaticSection('URL', url, {
      icon: '🌐',
      copy: detail.url || '',
      copyLabel: 'url',
    }),
    renderStaticSection('Folder', escapeHtml(detail.folder || 'general'), { icon: '📁' }),
    renderStaticSection('Description', description, { icon: '📝' }),
    renderStaticSection('Categories (AI suggested)', categories, { icon: '🧠' }),
  ];
}

function formatMultiline(value) {
  return escapeHtml(value).replace(/\n/g, '<br/>');
}

function renderStaticSection(label, value, options = {}) {
  const icon = options.icon ? `<span class="field-icon">${options.icon}</span>` : '';
  const copyBtn = options.copy ? renderCopyButton(options.copy, options.copyLabel || label) : '';
  return `
    <div class="detail-section">
      <div class="detail-section-header">
        <div class="field-label">${icon}${label}</div>
        ${copyBtn}
      </div>
      <div class="field-value">${value}</div>
    </div>
  `;
}

function renderEditableSections(detail) {
  if (!state.editDraft) {
    state.editDraft = createEditDraft(detail);
  }
  return [
    renderEditableField('App Name', 'field-app-name', getDraftValue('app_name', detail.app_name)),
    renderEditableField('Username', 'field-username', getDraftValue('username', detail.username || '')),
    renderEditableField('URL', 'field-url', getDraftValue('url', detail.url)),
    renderEditableField('Folder', 'field-folder', getDraftValue('folder', detail.folder || 'general')),
    renderEditableField(
      'Description',
      'field-description',
      getDraftValue('description', detail.description),
      true
    ),
    renderEditableField(
      'Tags (comma separated)',
      'field-tags',
      getDraftValue('tags', detail.tags.join(', '))
    ),
    renderEditableField(
      'Categories (comma separated)',
      'field-categories',
      getDraftValue('categories', detail.categories.join(', '))
    ),
  ];
}

function renderTimelineSections(detail) {
  const created = formatLocalDate(detail.created_at);
  const accessed = detail.last_accessed ? formatLocalDate(detail.last_accessed) : 'Never';
  return [
    renderStaticSection('Created', created, { icon: '🕑' }),
    renderStaticSection('Last Accessed', accessed, { icon: '📅' }),
  ];
}

function renderHistoryCallout() {
  const count = state.historyEntries.length;
  const label = count
    ? `${count} password history ${count === 1 ? 'entry' : 'entries'}`
    : 'No password history';
  return `
    <button id="history-open-btn" type="button" class="history-cta">
      <span class="history-cta-title">Password History <span class="chevron-icon chevron-right" aria-hidden="true">›</span></span>
      <span class="history-cta-subtitle">${label}</span>
    </button>
  `;
}

function renderHistoryPane(detail) {
  const count = state.historyEntries.length;
  const revealLabel = state.historyReveal ? 'Hide Password' : 'Reveal Password';
  const revealDisabled = count === 0 ? 'disabled' : '';
  const countdownLabel = state.historyReveal && state.historyCountdown > 0
    ? `<span class="password-timer">Auto hides in ${state.historyCountdown}s</span>`
    : '';
  const entries = count
    ? state.historyEntries.map((entry, index) => renderHistoryEntry(entry, index + 1)).join('')
    : '<div class="history-empty">No password history yet.</div>';
  return `
    <div class="history-pane">
      <div class="history-pane-header">
        <button id="history-back-btn" type="button" class="link-btn"><span class="chevron-icon chevron-left" aria-hidden="true">‹</span>Back to Credentials</button>
        <div class="history-pane-actions">
          ${countdownLabel}
          <button id="history-pane-reveal-btn" type="button" class="ghost-btn" ${revealDisabled}>${revealLabel}</button>
        </div>
      </div>
      <div class="history-pane-title">${escapeHtml(detail.app_name)}</div>
      <div class="history-pane-helper">Sorted newest to oldest.</div>
      <div class="history-pane-body">
        ${entries}
      </div>
    </div>
  `;
}

function renderHistoryEntry(entry, index) {
  const changed = formatHistoryDate(entry.changed_at_utc);
  const note = entry.note
    ? formatMultiline(entry.note)
    : '<span class="muted">None</span>';
  let secretValue = '<span class="history-secret-mask">***************</span>';
  if (state.historyReveal) {
    const secret = state.historySecrets[entry.history_id];
    if (typeof secret === 'undefined') {
      secretValue = '<span class="muted">Loading...</span>';
    } else if (!secret) {
      secretValue = '<span class="muted">Unavailable</span>';
    } else {
      secretValue = `<code>${escapeHtml(secret)}</code>`;
    }
  }
  return `
    <div class="history-entry">
      <div class="history-entry-number">${index}.</div>
      <div class="history-entry-content">
        <div class="history-entry-secret">${secretValue}</div>
        <div class="history-entry-meta">Changed on: ${changed}</div>
        <div class="history-entry-notes">Change Notes: ${note}</div>
      </div>
    </div>
  `;
}

function formatHistoryDate(value) {
  if (!value) return 'Unknown';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  const day = String(date.getDate()).padStart(2, '0');
  const month = new Intl.DateTimeFormat(undefined, { month: 'short' })
    .format(date)
    .toUpperCase();
  const year = date.getFullYear();
  const hours = String(date.getHours()).padStart(2, '0');
  const minutes = String(date.getMinutes()).padStart(2, '0');
  const seconds = String(date.getSeconds()).padStart(2, '0');
  const tzFormatter = new Intl.DateTimeFormat(undefined, { timeZoneName: 'short' });
  const tzParts = tzFormatter.formatToParts(date);
  const tz = tzParts.find((part) => part.type === 'timeZoneName')?.value || 'UTC';
  return `${day}-${month}-${year} ${hours}:${minutes}:${seconds} ${tz}`;
}

function formatLocalDate(value) {
  if (!value) return 'Unknown';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  const options = {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    timeZoneName: 'short',
  };
  return date.toLocaleString(undefined, options);
}

function renderPasswordSection(detail) {
  if (state.editMode) {
    if ((state.passwordEditing || detail.cred_id === -1) && state.editDraft) {
      const current = state.editDraft.password || '';
      const reasonBlock = renderPasswordReasonBlock(detail);
      return `
        <div class="detail-section">
          <div class="field-label">Password</div>
          <textarea id="field-password">${escapeHtml(current)}</textarea>
          <div class="helper-text">Secrets longer than 2000 characters are supported.</div>
          ${reasonBlock}
        </div>
      `;
    }
    return `
      <div class="detail-section">
        <div class="field-label">Password</div>
        <div class="field-value muted">Click "Edit Password" to load and edit this secret.</div>
      </div>
    `;
  }
  const passwordValue = state.revealedPassword
    ? `<code>${escapeHtml(state.revealedPassword)}</code>`
    : '<span class="muted">Click to reveal the password.</span>';
  const countdown = state.passwordCountdown > 0
    ? `<span class="password-timer">Auto hides in ${state.passwordCountdown}s</span>`
    : '';
  const copyBtn = state.revealedPassword
    ? renderCopyButton(state.revealedPassword, 'password', 'small')
    : '';
  const icon = state.revealedPassword ? renderEyeHideIcon() : renderEyeShowIcon();
  return `
    <div class="detail-section">
      <div class="password-header">
        <div class="field-label"><span class="field-icon">🔒</span>Password</div>
        <div class="password-header-actions">
          ${countdown}
          ${copyBtn}
        </div>
      </div>
      <div class="password-display">
        <div class="field-value password-value">${passwordValue}</div>
        <button id="password-eye-btn" type="button" class="password-toggle-btn" aria-label="Toggle password visibility">
          ${icon}
        </button>
      </div>
    </div>
  `;
}

function renderPasswordReasonBlock(detail) {
  if (!state.passwordEditing || !state.editDraft || detail.cred_id === -1) {
    return '';
  }
  const reasonValue = state.editDraft.password_reason || '';
  return `
    <div class="password-reason-block">
      <div class="field-label">Change notes (optional)</div>
      <textarea id="field-password-reason" placeholder="Why are you changing this password?">${escapeHtml(reasonValue)}</textarea>
      <div class="helper-text">Adding context helps future you remember why this secret changed.</div>
    </div>
  `;
}

function renderDetailTags(detail) {
  if (!detail.tags || detail.tags.length === 0) {
    return renderStaticSection('Tags', '(none)', { icon: '🏷️' });
  }
  const chips = detail.tags
    .map((tag) => `<span class="detail-tag-chip ${tagColorClass(tag)}" title="${escapeHtml(tag)}">${escapeHtml(tag)}</span>`)
    .join('');
  return `
    <div class="detail-section">
      <div class="field-label"><span class="field-icon">🏷️</span>Tags</div>
      <div class="detail-tag-line">${chips}</div>
    </div>
  `;
}

function bindCopyButtons() {
  if (!refs.detailPane) return;
  const buttons = refs.detailPane.querySelectorAll('.copy-chip[data-copy]');
  buttons.forEach((btn) => {
    btn.addEventListener('click', (event) => {
      const value = event.currentTarget.getAttribute('data-copy');
      const label = event.currentTarget.getAttribute('data-copy-label') || 'value';
      if (!value) return;
      navigator.clipboard
        .writeText(value)
        .then(() => {
          showToast({ type: 'success', title: 'Copied', message: `${label} copied.` });
        })
        .catch((err) => {
          showToast({ type: 'error', title: 'Copy failed', message: formatError(err) });
        });
    });
  });
}

function tagColorClass(tag) {
  const colors = ['blue', 'green', 'purple', 'amber'];
  const hash = Array.from(tag).reduce((sum, ch) => sum + ch.charCodeAt(0), 0);
  return colors[hash % colors.length];
}

function renderEyeShowIcon() {
  return `
    <svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true">
      <path fill="none" stroke="#475467" stroke-width="1.8" d="M1.5 12C2.6 8.5 6.1 5.5 12 5.5s9.4 3 10.5 6.5c-1.1 3.5-4.6 6.5-10.5 6.5S2.6 15.5 1.5 12Z" />
      <circle cx="12" cy="12" r="3.5" fill="none" stroke="#475467" stroke-width="1.8" />
    </svg>
  `;
}

function renderEyeHideIcon() {
  return `
    <svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true">
      <path fill="none" stroke="#475467" stroke-width="1.8" d="M1.5 12C2.6 8.5 6.1 5.5 12 5.5c2.9 0 5.3.7 7.1 1.9M22.5 12c-1.1 3.5-4.6 6.5-10.5 6.5-2.9 0-5.3-.7-7.1-1.9" />
      <circle cx="12" cy="12" r="3.5" fill="none" stroke="#475467" stroke-width="1.8" />
      <line x1="4" y1="4" x2="20" y2="20" stroke="#475467" stroke-width="1.8" />
    </svg>
  `;
}

function renderEditableField(label, id, value, multiline = false) {
  const safeValue = escapeHtml(value || '');
  if (multiline) {
    return `
      <div class="detail-section">
        <div class="field-label">${label}</div>
        <textarea id="${id}">${safeValue}</textarea>
      </div>
    `;
  }
  return `
    <div class="detail-section">
      <div class="field-label">${label}</div>
      <input id="${id}" type="text" value="${safeValue}" />
    </div>
  `;
}

function createEditDraft(detail) {
  return {
    app_name: detail.app_name || '',
    folder: detail.folder || 'general',
    username: detail.username || '',
    url: detail.url || '',
    description: detail.description || '',
    tags: detail.tags.join(', '),
    categories: detail.categories.join(', '),
    password: '',
    password_reason: '',
    password_reason_prefilled: false,
  };
}

function getDraftValue(field, fallback) {
  if (!state.editDraft) return fallback;
  return state.editDraft[field] ?? fallback;
}

function renderPill(value) {
  return `<span class="pill">${escapeHtml(value)}</span>`;
}

function renderCategoryPill(value) {
  return `<span class="pill" style="background:#fef3c7;color:#92400e;">${escapeHtml(value)}</span>`;
}

function bindDetailActions(detail) {
  const passwordBtn = document.getElementById("detail-password-btn");
  if (passwordBtn) {
    passwordBtn.addEventListener("click", () => handlePasswordButton(detail));
  }
  const editBtn = document.getElementById("detail-edit-btn");
  if (editBtn) {
    editBtn.addEventListener("click", () => startEditMode());
  }
  const saveBtn = document.getElementById("detail-save-btn");
  if (saveBtn) {
    saveBtn.addEventListener("click", () => saveCredentialChanges(detail));
  }
  const cancelBtn = document.getElementById("detail-cancel-btn");
  if (cancelBtn) {
    cancelBtn.addEventListener("click", cancelEditMode);
  }
  bindHistoryControls();
}

function bindPasswordFieldControls(detail) {
  const iconBtn = document.getElementById("password-eye-btn");
  if (iconBtn) {
    iconBtn.addEventListener("click", (event) => {
      event.preventDefault();
      handlePasswordButton(detail);
    });
  }
}

function bindEditInputs() {
  if (!state.editDraft) return;
  const fields = [
    { id: "field-app-name", key: "app_name" },
    { id: "field-folder", key: "folder" },
    { id: "field-username", key: "username" },
    { id: "field-url", key: "url" },
    { id: "field-description", key: "description" },
    { id: "field-tags", key: "tags" },
    { id: "field-categories", key: "categories" },
    { id: "field-password", key: "password" },
    { id: "field-password-reason", key: "password_reason" },
  ];
  fields.forEach(({ id, key }) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.addEventListener("input", (event) => {
      if (!state.editDraft) return;
      state.editDraft[key] = event.target.value;
    });
  });
}

function bindHistoryControls() {
  const openBtn = document.getElementById('history-open-btn');
  if (openBtn) {
    openBtn.addEventListener('click', () => {
      state.historyView = true;
      state.historyReveal = false;
      stopHistoryTimer();
      state.historyCountdown = 0;
      renderDetail();
      requestAnimationFrame(() => {
        if (refs.detailPane) {
          refs.detailPane.scrollTop = 0;
        }
      });
    });
  }
  const backBtn = document.getElementById('history-back-btn');
  if (backBtn) {
    backBtn.addEventListener('click', () => {
      state.historyView = false;
      state.historyReveal = false;
      stopHistoryTimer();
      state.historyCountdown = 0;
      renderDetail();
      requestAnimationFrame(() => {
        if (refs.detailPane) {
          refs.detailPane.scrollTop = 0;
        }
      });
    });
  }
  const revealBtn = document.getElementById('history-pane-reveal-btn');
  if (revealBtn) {
    revealBtn.addEventListener('click', async (event) => {
      event.preventDefault();
      event.stopPropagation();
      if (!state.historyEntries.length) return;
      if (!state.historyReveal) {
        await ensureHistorySecretsLoaded();
        state.historyReveal = true;
        startHistoryTimer();
        rerenderDetailPreservingScroll();
        return;
      }
      hideHistoryPasswords();
    });
  }
}

function rerenderDetailPreservingScroll() {
  const preservePane = refs.detailPane?.scrollTop ?? 0;
  renderDetail();
  requestAnimationFrame(() => {
    if (!refs.detailPane) return;
    refs.detailPane.scrollTop = preservePane;
    requestAnimationFrame(() => {
      if (refs.detailPane) {
        refs.detailPane.scrollTop = preservePane;
      }
    });
  });
}

async function ensureHistorySecretsLoaded() {
  const toLoad = state.historyEntries.filter((entry) => !state.historySecrets[entry.history_id]);
  for (const entry of toLoad) {
    try {
      const plain = await invoke('reveal_password_history_entry', { historyId: entry.history_id });
      state.historySecrets[entry.history_id] = plain;
    } catch (err) {
      console.error('Unable to reveal history entry', err);
      state.historySecrets[entry.history_id] = '';
    }
  }
}

async function startEditMode() {
  const detail = state.snapshot ? state.snapshot.selected : null;
  if (!detail) return;
  const ready = await ensureSessionForEditing();
  if (!ready) {
    return;
  }
  state.editMode = true;
  state.editDraft = createEditDraft(detail);
  state.passwordEditing = false;
  renderDetail();
}

function cancelEditMode() {
  state.editMode = false;
  state.editDraft = null;
  state.passwordEditing = false;
  if (state.creatingNew) {
    removePlaceholderCredential();
    state.creatingNew = false;
    state.placeholderCredential = null;
    fetchSnapshot();
  } else {
    renderDetail();
  }
}

function collectEditPayload(detail) {
  if (!state.editDraft) return null;
  const draft = state.editDraft;
  const appName = (draft.app_name || "").trim();
  if (!appName) {
    showToast({ type: 'error', title: 'Missing information', message: 'App name is required.' });
    return null;
  }
  const folder = (draft.folder || detail.folder || "general").trim() || "general";
  const username = (draft.username || "").trim();
  const basePassword = (draft.password || "").trim();
  let passwordValue = null;
  if (detail.cred_id === -1) {
    if (basePassword.length < 4) {
      showToast({ type: 'error', title: 'Weak password', message: 'Password must be at least 4 characters.' });
      return null;
    }
    passwordValue = basePassword;
  } else if (state.passwordEditing) {
    if (basePassword.length < 4) {
      showToast({ type: 'error', title: 'Weak password', message: 'Password must be at least 4 characters.' });
      return null;
    }
    passwordValue = basePassword;
  }
  const payload = {
    cred_id: detail.cred_id,
    app_name: appName,
    username,
    url: (draft.url || "").trim(),
    description: draft.description || "",
    folder,
    tags: splitList(draft.tags, true),
    categories: splitList(draft.categories, false),
    password: passwordValue,
  };
  if (detail.cred_id !== -1 && state.passwordEditing) {
    const reasonDraft = (draft.password_reason || '').trim();
    if (reasonDraft.length > 0) {
      payload.password_reason = reasonDraft;
    }
  }
  return payload;
}

async function saveCredentialChanges(detail) {
  const payload = collectEditPayload(detail);
  if (!payload) return;
  try {
    let updated;
    if (detail.cred_id === -1) {
      const { cred_id: _ignore, ...createPayload } = payload;
      updated = await invoke("create_credential_detail", { payload: createPayload });
      removePlaceholderCredential();
      state.creatingNew = false;
      state.placeholderCredential = null;
      showToast({
        type: 'success',
        title: 'Created',
        message: `${payload.app_name} added to the vault.`,
      });
    } else {
      updated = await invoke("update_credential_detail", { payload });
      showToast({
        type: 'success',
        title: 'Saved',
        message: `${payload.app_name} updated.`,
      });
    }
    state.editMode = false;
    state.editDraft = null;
    state.revealedPassword = null;
    state.passwordEditing = false;
    await fetchSnapshot();
    await loadCredentialDetail(updated.cred_id);
  } catch (err) {
    showToast({ type: 'error', title: 'Save failed', message: formatError(err) });
  }
}

async function handleReveal(credId) {
  try {
    const password = await invoke("reveal_password", { credId });
    state.revealedPassword = password;
    if (!state.editMode) {
      startPasswordTimer();
    }
    renderDetail();
    return password;
  } catch (err) {
    state.revealedPassword = null;
    showToast({ type: 'error', title: 'Reveal failed', message: formatError(err) });
    return null;
  }
}

async function handlePasswordButton(detail) {
  if (!state.editMode) {
    if (state.revealedPassword) {
      hidePassword();
    } else {
      await handleReveal(detail.cred_id);
    }
    return;
  }
  if (state.passwordEditing) {
    hidePassword();
    return;
  }
  await startPasswordEditing(detail);
}

async function startNewCredentialDraft() {
  if (!state.authenticated) {
    state.pendingNew = true;
    state.authenticated = false;
    toggleView();
    return;
  }
  const ready = await ensureSessionForEditing();
  if (!ready) {
    return;
  }
  if (!state.snapshot || state.creatingNew) {
    if (!state.snapshot) {
      showToast({ type: 'error', title: 'Unavailable', message: 'Load credentials before creating a new one.' });
    }
    return;
  }
  const draft = {
    cred_id: -1,
    app_name: 'New Credential',
    username: '',
    url: '',
    description: '',
    folder: state.folderFilter || 'general',
    tags: [],
    categories: [],
    created_at: new Date().toISOString(),
    last_accessed: 'Never',
  };
  state.placeholderCredential = { cred_id: -1, app_name: draft.app_name, folder: draft.folder, tags: [] };
  state.snapshot.credentials = [state.placeholderCredential, ...state.snapshot.credentials];
  state.snapshot.selected = draft;
  state.selectedCredentialId = -1;
  state.editMode = true;
  state.creatingNew = true;
  state.editDraft = createEditDraft(draft);
  state.passwordEditing = true;
  state.editDraft.password = '';
  state.editDraft.password_reason = '';
  state.editDraft.password_reason_prefilled = false;
  render();
}

async function startPasswordEditing(detail) {
  if (!state.editMode) return;
  if (!state.editDraft) {
    state.editDraft = createEditDraft(detail);
  }
  if (detail.cred_id === -1) {
    state.passwordEditing = true;
    renderDetail();
    return;
  }
  if (!state.passwordEditing) {
    const alreadyPrefilled = state.editDraft.password_reason_prefilled;
    if (!alreadyPrefilled) {
      const existingReason = (state.editDraft.password_reason || '').trim();
      if (!existingReason) {
        const previousNote = latestHistoryNote();
        if (previousNote) {
          state.editDraft.password_reason = previousNote;
        }
      }
      state.editDraft.password_reason_prefilled = true;
    }
  }
  let password = state.revealedPassword;
  if (!password) {
    password = await handleReveal(detail.cred_id);
    if (!password) {
      return;
    }
  }
  state.passwordEditing = true;
  state.editDraft.password = password;
  renderDetail();
  focusPasswordReasonField();
}

function latestHistoryNote() {
  if (!Array.isArray(state.historyEntries) || state.historyEntries.length === 0) {
    return '';
  }
  const first = state.historyEntries[0];
  if (!first || typeof first.note !== 'string') {
    return '';
  }
  return first.note;
}

function focusPasswordReasonField() {
  if (!state.passwordEditing) {
    return;
  }
  requestAnimationFrame(() => {
    const reasonField = document.getElementById('field-password-reason');
    if (!reasonField) {
      return;
    }
    reasonField.focus();
    const length = reasonField.value.length;
    try {
      reasonField.setSelectionRange(length, length);
    } catch (err) {
    }
  });
}

function setupSearchHandlers() {
  refs.folderSearch.addEventListener("input", (event) => {
    const term = event.target.value.toLowerCase();
    const buttons = Array.from(refs.folderList.querySelectorAll("button"));
    buttons.forEach((btn) => {
      if (btn.textContent.toLowerCase().includes(term) || btn.textContent.includes("All")) {
        btn.style.display = '';
      } else {
        btn.style.display = 'none';
      }
    });
  });

  const handleSearchInput = (event) => {
    state.searchText = event.target.value;
    scheduleSearchFetch();
  };

  refs.credentialSearch.addEventListener("input", handleSearchInput);
  refs.globalSearch.addEventListener("input", handleSearchInput);
}

function scheduleSearchFetch() {
  if (!state.authenticated) return;
  if (searchDebounceId) {
    clearTimeout(searchDebounceId);
  }
  searchDebounceId = window.setTimeout(() => {
    fetchSnapshot();
  }, SEARCH_DEBOUNCE_MS);
}


function populateProfileOptions(options) {
  if (!refs.vaultProfileOptions) return;
  const unique = Array.from(new Set(options || []));
  refs.vaultProfileOptions.innerHTML = unique
    .map((name) => `<option value="${escapeHtml(name)}"></option>`)
    .join('');
}

function setVaultContextStatus(message, variant = 'neutral') {
  if (!refs.vaultContextStatus) return;
  refs.vaultContextStatus.textContent = message || '';
  refs.vaultContextStatus.classList.remove('error', 'success');
  if (variant === 'error') {
    refs.vaultContextStatus.classList.add('error');
  } else if (variant === 'success') {
    refs.vaultContextStatus.classList.add('success');
  }
}

function renderVaultOptions() {
  if (!refs.vaultAdvancedPanel || !refs.vaultAdvancedToggle) return;
  const open = !!state.advancedPanelOpen;
  refs.vaultAdvancedPanel.classList.toggle('hidden', !open);
  refs.vaultAdvancedToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
  refs.vaultAdvancedToggle.textContent = open
    ? 'Hide advanced vault options'
    : 'Advanced vault options';
}

function renderVaultContextSummary(status) {
  let message = '';
  let variant = 'neutral';
  if (status?.initialized) {
    message = 'Existing vault detected';
    variant = 'success';
  } else if (status?.profile_exists) {
    message = 'Vault folder present; run setup to initialize.';
  } else {
    message = 'Profile folder will be created during setup.';
  }
  setVaultContextStatus(message, variant);
}

function applyVaultStatus(status) {
  state.vaultContext = {
    baseDir: status.base_dir || '',
    profile: status.profile || 'default',
    profilePath: status.profile_path || '',
    profileExists: !!status.profile_exists,
    initialized: !!status.initialized,
    availableProfiles: Array.isArray(status.available_profiles)
      ? status.available_profiles
      : [],
  };
  state.requiresSetup = !state.vaultContext.initialized;
  if (refs.vaultBaseDir && document.activeElement !== refs.vaultBaseDir) {
    refs.vaultBaseDir.value = state.vaultContext.baseDir;
  }
  if (refs.vaultProfile && document.activeElement !== refs.vaultProfile) {
    refs.vaultProfile.value = state.vaultContext.profile;
  }
  populateProfileOptions(state.vaultContext.availableProfiles);
  renderVaultContextSummary(status);
  renderLoginContextStack();
  renderLoginSubtitle();
  refreshContextBars();
  updateLoginForm();
}

function formatContextBarSummary() {
  const ctx = state.vaultContext || {};
  const profile = ctx.profile || 'default';
  const folder = ctx.profilePath || ctx.baseDir || '';
  const parts = [`Profile: ${profile}`];
  if (folder) {
    parts.push(`Location: ${folder}`);
  }
  const base = escapeHtml(parts.join(' • '));
  const hasSession = state.authenticated && state.sessionSecondsRemaining > 0;
  if (!hasSession) {
    return `<span class="context-primary">${base}</span>`;
  }
  const sessionLabel = escapeHtml(`Session Expires In: ${formatTimeRemaining(state.sessionSecondsRemaining)}`);
  const extendButton = state.sessionSecondsRemaining <= 120
    ? '<button type="button" class="session-extend-btn" id="session-extend-btn">Extend</button>'
    : '';
  return `
    <span class="context-primary">${base}</span>
    <span class="session-countdown">
      ${sessionLabel}
      ${extendButton}
    </span>
  `;
}

function renderLoginContextStack() {
  if (!refs.loginContextProfile || !refs.loginContextFolder) return;
  const ctx = state.vaultContext || {};
  const profile = ctx.profile || 'default';
  const folder = ctx.profilePath || ctx.baseDir || '';
  const locationText = folder || '(default)';
  if (refs.loginContextProfile) {
    refs.loginContextProfile.textContent = `Profile: ${profile}`;
  }
  if (refs.loginContextFolder) {
    refs.loginContextFolder.textContent = `Location: ${locationText}`;
  }
  if (refs.loginSubtitleProfile) {
    refs.loginSubtitleProfile.textContent = profile;
    refs.loginSubtitleProfile.title = `Profile location: ${locationText}`;
  }
  if (refs.loginLocationInfo) {
    refs.loginLocationInfo.title = 'Profiles let you keep separate vaults (work, personal, etc.). Switch or create new ones under Advanced Vault Options.';
  }
}

function renderLoginSubtitle() {
  if (!refs.loginSubtitle) return;
  const profile = state.vaultContext?.profile || 'default';
  const location =
    state.vaultContext?.profilePath || state.vaultContext?.baseDir || '(default)';
  const profileMarkup = `<span id="login-subtitle-profile" class="login-subtitle-profile">${escapeHtml(
    profile
  )}</span>`;
  const infoButton =
    '<button type="button" id="login-location-info" class="info-icon" aria-label="Show location">ⓘ</button>';
  if (state.requiresSetup) {
    refs.loginSubtitle.innerHTML = `Create a password for profile ${profileMarkup} ${infoButton}`;
  } else {
    refs.loginSubtitle.innerHTML = `Enter your password for profile ${profileMarkup} ${infoButton}`;
  }
  refs.loginSubtitleProfile = document.getElementById('login-subtitle-profile');
  refs.loginLocationInfo = document.getElementById('login-location-info');
  if (refs.loginSubtitleProfile) {
    refs.loginSubtitleProfile.title = `Profile location: ${location}`;
  }
  if (refs.loginLocationInfo) {
    refs.loginLocationInfo.title = 'Profiles let you keep separate vaults (work, personal, etc.). Switch or create new ones under Advanced Vault Options.';
  }
}

function refreshContextBars() {
  const content = formatContextBarSummary();
  if (refs.loginContextBar) {
    refs.loginContextBar.innerHTML = content;
  }
  if (refs.appContextBar) {
    refs.appContextBar.innerHTML = content;
    attachSessionExtendHandler();
  }
}

function attachSessionExtendHandler() {
  const btn = document.getElementById('session-extend-btn');
  if (!btn) return;
  btn.addEventListener('click', async () => {
    await promptReauth('Re-authenticate to extend your session.');
    await refreshSessionTimer();
  });
}

async function handleVaultContextApply() {
  if (!refs.vaultBaseDir || !refs.vaultProfile) return;
  const baseDir = refs.vaultBaseDir.value.trim();
  const profile = refs.vaultProfile.value.trim();
  if (!baseDir || !profile) {
    setVaultContextStatus('Vault folder and profile are required.', 'error');
    return;
  }
  setVaultContextStatus('Saving selection...', 'neutral');
  try {
    const status = await invoke('update_vault_context', { baseDir, profile });
    applyVaultStatus(status);
    state.advancedPanelOpen = false;
    renderVaultOptions();
    setVaultContextStatus('Vault context updated.', 'success');
    if (refs.loginPassword) {
      refs.loginPassword.focus();
    }
  } catch (err) {
    setVaultContextStatus(formatError(err), 'error');
  }
}

async function handleVaultContextReset() {
  setVaultContextStatus('Resetting to default...', 'neutral');
  try {
    const status = await invoke('reset_vault_context');
    applyVaultStatus(status);
    state.advancedPanelOpen = false;
    renderVaultOptions();
  } catch (err) {
    setVaultContextStatus(formatError(err), 'error');
  }
}

function setupVaultContextHandlers() {
  if (!refs.vaultAdvancedToggle) return;
  renderVaultOptions();
  refs.vaultAdvancedToggle.addEventListener('click', () => {
    state.advancedPanelOpen = !state.advancedPanelOpen;
    renderVaultOptions();
  });
  refs.vaultApply?.addEventListener('click', handleVaultContextApply);
  refs.vaultReset?.addEventListener('click', handleVaultContextReset);
  const submitOnEnter = (event) => {
    if (event.key === 'Enter') {
      event.preventDefault();
      handleVaultContextApply();
    }
  };
  refs.vaultBaseDir?.addEventListener('keydown', submitOnEnter);
  refs.vaultProfile?.addEventListener('keydown', submitOnEnter);
}

async function ensureContextSyncedFromForm() {
  if (!refs.vaultBaseDir || !refs.vaultProfile) {
    return true;
  }
  const baseDir = refs.vaultBaseDir.value.trim();
  const profile = refs.vaultProfile.value.trim();
  if (!baseDir || !profile) {
    setVaultContextStatus('Vault folder and profile are required.', 'error');
    return false;
  }
  if (
    baseDir === state.vaultContext.baseDir &&
    profile === state.vaultContext.profile
  ) {
    return true;
  }
  try {
    const status = await invoke('update_vault_context', { baseDir, profile });
    applyVaultStatus(status);
    return true;
  } catch (err) {
    setVaultContextStatus(formatError(err), 'error');
    return false;
  }
}

function setupAuthHandlers() {
  refs.loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    await attemptLogin();
  });
  refs.logoutBtn.addEventListener("click", async () => {
    try {
      await invoke("logout");
    } catch (err) {
      console.error(err);
    }
    stopSessionTimer();
    state.authenticated = false;
    state.snapshot = null;
    refs.credentialList.innerHTML = "";
    refs.detailPane.innerHTML = "";
    await refreshVaultStatus();
    toggleView();
    clearToast();
  });
  if (refs.newCredentialBtn) {
    refs.newCredentialBtn.addEventListener('click', () => startNewCredentialDraft());
  }
}

async function attemptLogin() {
  const password = refs.loginPassword.value.trim();
  if (!password) {
    setLoginFeedback("Password required", 'error');
    return;
  }
  const contextReady = await ensureContextSyncedFromForm();
  if (!contextReady) {
    return;
  }
  try {
    setLoginFeedback('');
    if (state.requiresSetup) {
      const confirm = refs.loginConfirm.value.trim();
      if (confirm !== password) {
        setLoginFeedback("Passwords do not match", 'error');
        return;
      }
      setLoginFeedback("Creating vault...", 'status');
      await invoke("setup_password", { password, confirm });
      setLoginFeedback("Password created. Loading credentials...", 'status');
      refs.loginConfirm.value = "";
      state.requiresSetup = false;
    } else {
      setLoginFeedback("Validating password...", 'status');
      await invoke("login", { password });
      setLoginFeedback("Password verified. Loading credentials...", 'status');
    }
    refs.loginPassword.value = "";
    setLoginFeedback('');
    state.authenticated = true;
    toggleView();
    await refreshSessionTimer();
    const loaded = await fetchSnapshot();
    if (!loaded) {
      state.authenticated = false;
      toggleView();
      setLoginFeedback("Unable to load credentials. Try again.", 'error');
    } else {
      setLoginFeedback('');
      if (state.pendingNew) {
        state.pendingNew = false;
        await startNewCredentialDraft();
      }
    }
  } catch (err) {
    const rawMessage = typeof err === "string"
      ? err
      : err && typeof err === "object" && "message" in err
        ? err.message
        : "Unlock failed";
    const normalized = (rawMessage || "").toString().toLowerCase();
    if (normalized.includes("invalid master password")) {
      setLoginFeedback("Invalid password", 'error');
    } else if (normalized.includes("decryption failure") || normalized.includes("invalid credential")) {
      setLoginFeedback("Invalid credential", 'error');
    } else {
      setLoginFeedback((rawMessage || "Unlock failed").replace(/_/g, " "), 'error');
    }
  }
}

function setupClearFilterHandlers() {
  refs.clearFolderBtn?.addEventListener('click', () => {
    if (state.folderFilter === null) return;
    state.folderFilter = null;
    fetchSnapshot();
  });
  refs.clearTagBtn?.addEventListener('click', () => {
    if (state.tagFilter === null) return;
    state.tagFilter = null;
    fetchSnapshot();
  });
  refs.clearSearchBtn?.addEventListener('click', () => {
    if (!state.searchText && !refs.credentialSearch.value) return;
    state.searchText = '';
    refs.credentialSearch.value = '';
    refs.globalSearch.value = '';
    fetchSnapshot();
  });
}

function toggleView() {
  if (state.authenticated) {
    refs.loginScreen.classList.add("hidden");
    refs.appShell.classList.remove("hidden");
  } else {
    refs.appShell.classList.add("hidden");
    refs.loginScreen.classList.remove("hidden");
    refs.loginStatus.textContent = "";
    updateLoginForm();
  }
}

async function checkSession() {
  try {
    const authed = await invoke("check_session");
    state.authenticated = authed;
    toggleView();
    if (authed) {
      await refreshSessionTimer();
      fetchSnapshot();
    } else {
      stopSessionTimer();
    }
  } catch (err) {
    console.error(err);
    state.authenticated = false;
    toggleView();
  }
}

async function refreshVaultStatus() {
  try {
    const status = await invoke("vault_status");
    applyVaultStatus(status);
  } catch (err) {
    console.error(err);
    setVaultContextStatus('Unable to load vault information.', 'error');
  }
}

function updateLoginForm() {
  if (state.requiresSetup) {
    refs.loginTitle.textContent = "Create FerrumVault Password";
    renderLoginSubtitle();
    refs.loginConfirm.classList.remove("hidden");
  } else {
    refs.loginTitle.textContent = "Unlock FerrumVault";
    renderLoginSubtitle();
    refs.loginConfirm.classList.add("hidden");
    refs.loginConfirm.value = "";
  }
}

async function init() {
  await loadAppMetadata();
  setupRefs();
  setupMenuHandlers();
  setupSearchHandlers();
  setupClearFilterHandlers();
  setupAuthHandlers();
  setupVaultContextHandlers();
  registerOAuthDeepLinkListener();
  initAutoCapControl();
  await refreshVaultStatus();
  await checkSession();
}

window.addEventListener("DOMContentLoaded", init);
