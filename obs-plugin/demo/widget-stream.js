"use strict";

(() => {
  const apiBase = "http://127.0.0.1:4041";
  const socketUrl = "ws://127.0.0.1:4043/api/widget/events";
  const tokenStorageKey = "donationalerts-provider.widget-token";
  const pageUrl = new URL(window.location.href);
  const tokenInput = document.getElementById("widget-token");
  const connectButton = document.getElementById("connect");
  const previewButton = document.getElementById("preview");
  const settingsToggle = document.getElementById("settings-toggle");
  const settingsPanel = document.getElementById("settings-panel");
  const statusElement = document.getElementById("status");
  const widgetType = document.body.dataset.widget;
  const dataSource = document.body.dataset.source || "plugin";
  const isOverlayOnly = pageUrl.searchParams.get("overlay") === "1";
  const isPreviewMode = pageUrl.searchParams.get("preview") === "1";
  const maxFeedItems = 5;
  let token = "";
  let connectionVerified = false;
  let connectionInFlight = false;
  let socket = null;
  let reconnectTimer = null;
  let alertTimer = null;
  let pendingAlerts = [];
  let recentDonations = [];
  let seenDonationIds = new Set();

  if (isOverlayOnly) document.body.classList.add("overlay-only");
  if (isPreviewMode && !isOverlayOnly) document.body.classList.add("preview-mode");

  // Keep the widget key out of the visible URL after capturing it.
  const queryToken = pageUrl.searchParams.get("token");
  if (queryToken !== null) {
    token = queryToken.trim();
    pageUrl.searchParams.delete("token");
    try {
      localStorage.setItem(tokenStorageKey, token);
    } catch (error) {
      setStatus(`Не удалось сохранить ключ в браузере: ${error.message}`, "error");
    }
    try {
      window.history.replaceState(null, "", pageUrl);
    } catch (error) {
      setStatus(`Не удалось убрать ключ из адреса: ${error.message}`, "error");
    }
  } else {
    try {
      token = localStorage.getItem(tokenStorageKey) || "";
    } catch (error) {
      setStatus(`Не удалось прочитать ключ из браузера: ${error.message}`, "error");
    }
  }

  if (tokenInput) tokenInput.value = token;
  if (settingsPanel && settingsToggle && !isOverlayOnly) {
    settingsPanel.hidden = false;
    settingsToggle.setAttribute("aria-expanded", "true");
    settingsToggle.textContent = "Скрыть настройки";
  }

  function setStatus(message, state = "idle") {
    if (!statusElement) return;
    statusElement.textContent = message;
    statusElement.dataset.state = state;
  }

  function setSettingsOpen(open) {
    if (!settingsPanel || !settingsToggle || isOverlayOnly) return;
    settingsPanel.hidden = !open;
    settingsToggle.setAttribute("aria-expanded", String(open));
    settingsToggle.textContent = open
      ? "Скрыть настройки"
      : (connectionVerified ? "Настройки ключа" : "Настроить");
    settingsToggle.setAttribute("aria-label", open ? "Скрыть настройки ключа" : "Показать настройки ключа");
    if (tokenInput) tokenInput.disabled = connectionInFlight;
    if (connectButton) {
      connectButton.disabled = connectionInFlight || (connectionVerified && !open);
      connectButton.textContent = connectionVerified ? "Сохранить и подключить" : "Подключить";
    }
  }

  function showConnectionSettings() {
    setSettingsOpen(true);
    if (connectButton) connectButton.disabled = connectionInFlight;
    if (tokenInput) {
      tokenInput.disabled = connectionInFlight;
      tokenInput.focus();
    }
  }

  function normalizeDonation(value) {
    let donation = value;
    for (let depth = 0; depth < 5 && donation && typeof donation === "object"; depth += 1) {
      if ("amount" in donation) return donation;
      donation = donation.donation || donation.data || donation.payload ||
        donation.alert || donation.info || donation.event || donation.raw;
    }
    return value && typeof value === "object" ? value : null;
  }

  function donationIdentity(donation) {
    if (donation.id !== undefined && donation.id !== null) return `id:${donation.id}`;
    return `fallback:${donation.username || donation.name || ""}:${donation.amount || ""}:` +
      `${donation.currency || ""}:${donation.created_at || ""}:${donation.message || ""}`;
  }

  function addDonation(donation, isNewEvent) {
    if (!donation) return;
    const identity = donationIdentity(donation);
    if (seenDonationIds.has(identity)) return;
    seenDonationIds.add(identity);
    recentDonations = [donation, ...recentDonations].slice(0, maxFeedItems);
    if (widgetType === "feed") renderFeed();
    if (isNewEvent && widgetType === "alert") {
      pendingAlerts.push(donation);
      showNextAlert();
    }
  }

  function formatAmount(donation) {
    const amount = donation.amount ?? "";
    const currency = donation.currency || "";
    return `${amount} ${currency}`.trim();
  }

  function renderFeed() {
    const list = document.getElementById("feed-list");
    list.replaceChildren();
    if (recentDonations.length === 0) {
      const empty = document.createElement("div");
      empty.className = "feed-empty";
      empty.textContent = "Пока нет донатов";
      list.append(empty);
      return;
    }

    for (const donation of recentDonations) {
      const row = document.createElement("article");
      row.className = "feed-row";
      const donor = document.createElement("strong");
      donor.className = "feed-donor";
      donor.textContent = donation.username || donation.name || "Аноним";
      const amount = document.createElement("span");
      amount.className = "feed-amount";
      amount.textContent = formatAmount(donation);
      row.append(donor, amount);
      if (donation.message) {
        const message = document.createElement("p");
        message.className = "feed-message";
        message.textContent = donation.message;
        row.append(message);
      }
      list.append(row);
    }
  }

  function displayAlert(donation) {
    const alert = document.getElementById("alert");
    document.getElementById("donor").textContent = donation.username || donation.name || "Аноним";
    document.getElementById("amount").textContent = formatAmount(donation);
    document.getElementById("message").textContent = donation.message || "";
    alert.classList.remove("leaving", "visible", "entering");
    void alert.offsetWidth;
    alert.classList.add("visible", "entering");
    alertTimer = window.setTimeout(() => {
      alert.classList.remove("entering");
      alert.classList.add("leaving");
      alertTimer = window.setTimeout(() => {
        alert.classList.remove("visible", "leaving");
        alertTimer = null;
        showNextAlert();
      }, 350);
    }, 6500);
  }

  function showNextAlert() {
    if (widgetType !== "alert" || alertTimer !== null || pendingAlerts.length === 0) return;
    displayAlert(pendingAlerts.shift());
  }

  function onSocketMessage(message) {
    let event;
    try {
      event = JSON.parse(message.data);
    } catch {
      setStatus("Плагин прислал некорректное событие.", "error");
      return;
    }
    if (event.type === "status") {
      const realtimeMessage = event.connected ? "Realtime-события подключены." :
        (event.message || "Realtime-канал пока не подключён.");
      const message = dataSource === "donationalerts-api"
        ? `История загружается через API DonationAlerts; ${realtimeMessage}`
        : realtimeMessage;
      setStatus(message, event.connected ? "ok" : "error");
      return;
    }
    if (event.type === "donation") addDonation(normalizeDonation(event.donation || event.data || event), true);
  }

  function connectSocket() {
    if (socket || !token) return;
    setStatus("Подключаю realtime-события…");
    let nextSocket;
    try {
      nextSocket = new WebSocket(socketUrl, ["donationalerts-widget-v1", token]);
    } catch (error) {
      setStatus(`Не удалось подключить WebSocket: ${error.message}`, "error");
      scheduleReconnect();
      return;
    }
    socket = nextSocket;
    nextSocket.addEventListener("open", () => {
      if (socket === nextSocket) setStatus("WebSocket подключён; ожидаю донаты.", "ok");
    });
    nextSocket.addEventListener("message", onSocketMessage);
    nextSocket.addEventListener("error", () => {
      if (socket === nextSocket) setStatus("Ошибка WebSocket локального плагина.", "error");
    });
    nextSocket.addEventListener("close", event => {
      if (socket !== nextSocket) return;
      socket = null;
      setStatus(`WebSocket отключён (код ${event.code}); повторное подключение через 3 секунды.`, "error");
      scheduleReconnect();
    });
  }

  function scheduleReconnect() {
    if (!reconnectTimer && token) {
      reconnectTimer = window.setTimeout(() => {
        reconnectTimer = null;
        connectSocket();
      }, 3000);
    }
  }

  async function loadDonationAlertsHistory(widgetToken) {
    const response = await fetch(`${apiBase}/api/v1/alerts/donations?per_page=30`, {
      cache: "no-store",
      headers: { Authorization: `Bearer ${widgetToken}` }
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = new Error(body.error || `DonationAlerts API: HTTP ${response.status}`);
      error.status = response.status;
      throw error;
    }
    if (!Array.isArray(body.data)) throw new Error("DonationAlerts API вернул некорректный список донатов.");
    return body.data;
  }

  async function connect() {
    const nextToken = tokenInput ? tokenInput.value.trim() : token;
    if (!nextToken) {
      setStatus("Введите временный ключ с доступом к событиям донатов.", "error");
      if (tokenInput) tokenInput.focus();
      return;
    }
    token = nextToken;
    connectionInFlight = true;
    if (socket) {
      socket.close();
      socket = null;
    }
    if (reconnectTimer) {
      window.clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    setSettingsOpen(true);
    let storageWarning = "";
    try {
      try {
        localStorage.setItem(tokenStorageKey, token);
      } catch (error) {
        storageWarning = ` Ключ не сохранён в браузере: ${error.message}`;
      }
      // The feed uses the DonationAlerts-compatible route; the alert uses the provider snapshot.
      if (dataSource === "donationalerts-api") {
        const donations = await loadDonationAlertsHistory(token);
        recentDonations = [];
        seenDonationIds = new Set();
        for (const donation of donations) addDonation(normalizeDonation(donation), false);
        renderFeed();
        connectionVerified = true;
        connectionInFlight = false;
        setStatus(`Подключено: история получена из API DonationAlerts через прокси OBS.${storageWarning}`,
          storageWarning ? "error" : "ok");
        setSettingsOpen(false);
        connectSocket();
        return;
      }
      const response = await fetch(`${apiBase}/api/widget/data`, {
        cache: "no-store",
        headers: { Authorization: `Bearer ${token}` }
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) {
        const error = new Error(body.error || `HTTP ${response.status}`);
        error.status = response.status;
        throw error;
      }
      if (!Array.isArray(body.donations)) throw new Error("Плагин вернул некорректную историю донатов.");
      recentDonations = [];
      seenDonationIds = new Set();
      for (const donation of body.donations) addDonation(normalizeDonation(donation), false);
      if (widgetType === "feed") renderFeed();
      connectionVerified = true;
      connectionInFlight = false;
      setStatus(`Подключено к локальному плагину; загружена история донатов.${storageWarning}`,
        storageWarning ? "error" : "ok");
      setSettingsOpen(false);
      connectSocket();
    } catch (error) {
      connectionVerified = false;
      connectionInFlight = false;
      token = "";
      if (error.status === 401 || error.status === 403) {
        if (tokenInput) tokenInput.value = "";
        try {
          localStorage.removeItem(tokenStorageKey);
        } catch (storageError) {
          storageWarning = ` Не удалось удалить недействительный ключ из браузера: ${storageError.message}`;
        }
      }
      setSettingsOpen(true);
      setStatus(`Ошибка подключения: ${error.message}.${storageWarning}`, "error");
    }
  }

  if (settingsToggle) {
    settingsToggle.addEventListener("click", () => {
      const shouldOpen = settingsPanel.hidden;
      if (shouldOpen) {
        showConnectionSettings();
      } else {
        setSettingsOpen(false);
      }
    });
  }

  if (previewButton) {
    previewButton.addEventListener("click", () => {
      const donation = {
        id: `preview-${Date.now()}`,
        username: "Тестовый зритель",
        amount: 150,
        currency: "RUB",
        message: "Тестовое сообщение для проверки виджета"
      };
      addDonation(donation, true);
      setStatus("Превью показано. Следующие алерты поступят из подключённого источника.", "ok");
    });
  }

  if (connectButton) connectButton.addEventListener("click", connect);
  if (token) void connect();
  if (widgetType === "feed") renderFeed();

  window.addEventListener("beforeunload", () => {
    if (reconnectTimer) window.clearTimeout(reconnectTimer);
    if (alertTimer) window.clearTimeout(alertTimer);
    if (socket) socket.close();
  });
})();
