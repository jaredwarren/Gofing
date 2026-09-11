// Gofing - Real-Time Dashboard Client Logic with Device Drawer
document.addEventListener('DOMContentLoaded', () => {
  let devicesMap = new Map(); // keyed by device id
  let currentCategory = 'all';
  let searchQuery = '';
  let openDeviceId = null;
  let activeTab = 'overview';

  const ssidNameEl = document.getElementById('ssidName');
  const subnetCidrEl = document.getElementById('subnetCidr');
  const statTotalEl = document.getElementById('statTotal');
  const statOnlineEl = document.getElementById('statOnline');
  const statOfflineEl = document.getElementById('statOffline');
  const statGatewayEl = document.getElementById('statGateway');
  const statLocalIPEl = document.getElementById('statLocalIP');
  const deviceTableBody = document.getElementById('deviceTableBody');
  const searchInput = document.getElementById('searchInput');
  const rescanBtn = document.getElementById('rescanBtn');
  const scanBtnText = document.getElementById('scanBtnText');
  const dhcpImportBtn = document.getElementById('dhcpImportBtn');
  const dhcpFileInput = document.getElementById('dhcpFileInput');
  const progressContainer = document.getElementById('progressContainer');
  const progressBarFill = document.getElementById('progressBarFill');
  const categoryPillsContainer = document.getElementById('categoryPills');
  const activityFeed = document.getElementById('activityFeed');
  const alertsEnabledChk = document.getElementById('alertsEnabledChk');
  const notifyMacosChk = document.getElementById('notifyMacosChk');
  const alertOnlineChk = document.getElementById('alertOnlineChk');
  const alertOfflineChk = document.getElementById('alertOfflineChk');
  const alertCooldownSel = document.getElementById('alertCooldownSel');
  const versionBadgeEl = document.getElementById('versionBadge');

  const deviceDrawer = document.getElementById('deviceDrawer');
  const drawerCloseBtn = document.getElementById('drawerCloseBtn');
  const drawerTypeIcon = document.getElementById('drawerTypeIcon');
  const drawerDeviceName = document.getElementById('drawerDeviceName');
  const drawerDeviceSub = document.getElementById('drawerDeviceSub');
  const drawerIP = document.getElementById('drawerIP');
  const drawerMAC = document.getElementById('drawerMAC');
  const drawerVendor = document.getElementById('drawerVendor');
  const drawerModel = document.getElementById('drawerModel');
  const drawerLatency = document.getElementById('drawerLatency');
  const drawerStatus = document.getElementById('drawerStatus');
  const drawerFirstSeen = document.getElementById('drawerFirstSeen');
  const drawerLastSeen = document.getElementById('drawerLastSeen');
  const drawerServices = document.getElementById('drawerServices');
  const editCustomName = document.getElementById('editCustomName');
  const editTypeOverride = document.getElementById('editTypeOverride');
  const editNote = document.getElementById('editNote');
  const saveDeviceBtn = document.getElementById('saveDeviceBtn');
  const saveStatus = document.getElementById('saveStatus');
  const historyList = document.getElementById('historyList');
  const drawerTabs = document.getElementById('drawerTabs');
  const btnDeepProbe = document.getElementById('btnDeepProbe');
  const toolProbeStatus = document.getElementById('toolProbeStatus');
  const toolProbeCard = document.getElementById('toolProbeCard');
  const btnResolveName = document.getElementById('btnResolveName');
  const btnRecheck = document.getElementById('btnRecheck');
  const toolRecheckStatus = document.getElementById('toolRecheckStatus');
  const toolRecheckOutput = document.getElementById('toolRecheckOutput');
  const toolResolveStatus = document.getElementById('toolResolveStatus');
  const toolResolveOutput = document.getElementById('toolResolveOutput');
  const btnScanPorts = document.getElementById('btnScanPorts');
  const btnScanPortsDeep = document.getElementById('btnScanPortsDeep');
  const portsScanStatus = document.getElementById('portsScanStatus');
  const portsList = document.getElementById('portsList');

  const copyIPBtn = document.getElementById('copyIPBtn');
  const copyMACBtn = document.getElementById('copyMACBtn');

  copyIPBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    const text = drawerIP.textContent;
    if (text && text !== '—') copyToClipboard(text, copyIPBtn);
  });

  copyMACBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    const text = drawerMAC.textContent;
    if (text && text !== '—' && text !== 'Unspecified') copyToClipboard(text, copyMACBtn);
  });

  function copyToClipboard(text, btnEl) {
    navigator.clipboard.writeText(text).then(() => {
      const origHTML = btnEl.innerHTML;
      btnEl.classList.add('copied');
      btnEl.innerHTML = `<span style="font-size:11px; font-weight:600;">✓ Copied</span>`;
      setTimeout(() => {
        btnEl.classList.remove('copied');
        btnEl.innerHTML = origHTML;
      }, 1500);
    }).catch(err => console.error('Clipboard copy error:', err));
  }

  fetchVersionInfo();
  fetchNetworkInfo();
  fetchInitialDevices();
  fetchActivity();
  fetchSettings();
  initSSE();

  const searchClearBtn = document.getElementById('searchClearBtn');

  function syncSearchClear() {
    if (!searchClearBtn) return;
    searchClearBtn.hidden = !searchInput.value;
  }

  searchInput.addEventListener('input', (e) => {
    searchQuery = e.target.value.toLowerCase().trim();
    syncSearchClear();
    renderTable();
  });

  if (searchClearBtn) {
    searchClearBtn.addEventListener('click', () => {
      searchInput.value = '';
      searchQuery = '';
      syncSearchClear();
      searchInput.focus();
      renderTable();
    });
  }

  categoryPillsContainer.addEventListener('click', (e) => {
    const pill = e.target.closest('.pill');
    if (pill) {
      document.querySelectorAll('.pill').forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      currentCategory = pill.dataset.category;
      renderTable();
    }
  });

  const activityFilterPills = document.getElementById('activityFilterPills');
  if (activityFilterPills) {
    activityFilterPills.addEventListener('click', (e) => {
      const pill = e.target.closest('.act-pill');
      if (!pill) return;
      const filter = pill.dataset.actFilter;
      if (!filter || filter === currentActivityFilter) return;

      activityFilterPills.querySelectorAll('.act-pill').forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      currentActivityFilter = filter;
      renderFilteredActivity();
    });
  }

  if (activityFeed) {
    activityFeed.addEventListener('click', (e) => {
      const item = e.target.closest('.activity-item.is-clickable');
      if (!item) return;
      const devId = item.dataset.deviceId;
      if (!devId) return;
      const dev = findDevice(devId);
      if (dev) {
        openDrawer(dev.id, 'overview');
      }
    });
  }

  rescanBtn.addEventListener('click', () => triggerScan());
  dhcpImportBtn.addEventListener('click', () => dhcpFileInput.click());
  dhcpFileInput.addEventListener('change', async () => {
    const file = dhcpFileInput.files && dhcpFileInput.files[0];
    dhcpFileInput.value = '';
    if (!file) return;
    try {
      const text = await file.text();
      const res = await fetch('/api/dhcp/import', {
        method: 'POST',
        headers: { 'Content-Type': 'text/plain' },
        body: text
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        alert(data.message || 'DHCP import failed — paste a client list with names, MACs, and IPs.');
        return;
      }
      dhcpImportBtn.title = `Imported ${data.created || 0} new, ${data.updated || 0} updated`;
    } catch (err) {
      console.error('DHCP import error', err);
      alert('DHCP import failed');
    }
  });

  drawerCloseBtn.addEventListener('click', closeDrawer);
  deviceDrawer.addEventListener('click', (e) => {
    if (e.target === deviceDrawer) closeDrawer();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && deviceDrawer.classList.contains('open')) closeDrawer();
  });

  drawerTabs.addEventListener('click', (e) => {
    const tab = e.target.closest('.drawer-tab');
    if (!tab) return;
    setActiveTab(tab.dataset.tab);
  });

  saveDeviceBtn.addEventListener('click', saveDeviceEdits);
  if (btnDeepProbe) btnDeepProbe.addEventListener('click', runDeepProbe);
  btnResolveName.addEventListener('click', resolveDeviceName);
  if (btnRecheck) btnRecheck.addEventListener('click', recheckDevice);
  btnScanPorts.addEventListener('click', () => startPortScan('common'));
  btnScanPortsDeep.addEventListener('click', () => startPortScan('deep'));

  function deviceKey(dev) {
    return dev.id || (dev.mac ? dev.mac : `ip:${dev.ip}`);
  }

  function findDevice(idOrKey) {
    if (!idOrKey) return null;
    if (devicesMap.has(idOrKey)) return devicesMap.get(idOrKey);
    const base = idOrKey.includes('/') ? idOrKey.split('/').pop() : idOrKey;
    for (const dev of devicesMap.values()) {
      if (dev.id === idOrKey || dev.id === base || dev.mac === idOrKey || dev.mac === base || dev.ip === idOrKey) {
        return dev;
      }
    }
    return null;
  }

  function displayName(dev) {
    if (dev.custom_name) return dev.custom_name;
    if (dev.hostname && !isGenericLabel(dev.hostname)) return dev.hostname;
    if (dev.model && !isGenericLabel(dev.model)) return dev.model;
    if (dev.vendor && !isGenericLabel(dev.vendor)) return dev.vendor;
    return dev.ip || 'Discovered Device';
  }

  function isGenericLabel(s) {
    const v = String(s || '').trim().toLowerCase();
    return [
      'apple device', 'generic device', 'network device',
      'standard network hardware', 'unknown vendor', 'generic', 'device',
      'unknown', 'unknown device',
      'private / randomized mac', 'private mac', 'randomized mac', 'private / randomized mac address'
    ].includes(v);
  }

  function formatNameSource(src) {
    switch (src) {
      case 'host': return 'This Mac';
      case 'dhcp': return 'Router DHCP';
      case 'netbios': return 'NetBIOS';
      case 'arp': return 'Bonjour / ARP';
      case 'mdns': return 'Bonjour';
      case 'upnp': return 'UPnP';
      case 'dns': return 'DNS';
      case 'tls': return 'TLS Cert';
      case 'cast': return 'Cast';
      case 'http': return 'HTTP title';
      default: return '—';
    }
  }

  function displayType(dev) {
    return dev.device_type_override || dev.device_type || 'Generic Device';
  }

  function upsertDevice(dev) {
    const key = deviceKey(dev);
    // Drop stale keys after remount (same MAC/IP, different scoped id).
    if (dev.id || dev.mac || dev.ip) {
      for (const [k, v] of devicesMap.entries()) {
        if (k === key) continue;
        const sameMAC = dev.mac && v.mac && v.mac === dev.mac;
        const sameIP = dev.ip && v.ip && v.ip === dev.ip;
        if (sameMAC || sameIP) {
          devicesMap.delete(k);
        }
      }
    }
    devicesMap.set(key, dev);
    if (openDeviceId && (openDeviceId === key || openDeviceId === dev.id)) {
      openDeviceId = key;
      fillDrawer(dev);
    }
  }

  function fetchVersionInfo() {
    fetch('/api/version')
      .then(res => res.json())
      .then(info => {
        if (!versionBadgeEl) return;
        if (info && info.version) {
          const timeStr = info.build_time && info.build_time !== 'unknown' ? ` • ${info.build_time}` : '';
          versionBadgeEl.textContent = `v${info.version}${timeStr}`;
          versionBadgeEl.setAttribute('title', `Gofing v${info.version} (Built: ${info.build_time || 'unknown'})`);
        }
      })
      .catch(err => {
        console.warn('Failed to fetch version info:', err);
        if (versionBadgeEl) versionBadgeEl.style.display = 'none';
      });
  }

  function fetchNetworkInfo() {
    fetch('/api/network')
      .then(res => res.json())
      .then(info => {
        ssidNameEl.textContent = info.ssid || 'Local Network';
        subnetCidrEl.textContent = info.subnet_cidr || '';
        statGatewayEl.textContent = info.gateway_ip || '—';
        statLocalIPEl.textContent = `My IP: ${info.ip || '—'} (${info.interface_name || ''})`;
      })
      .catch(err => console.error('Failed to fetch network info:', err));
  }

  function fetchInitialDevices() {
    fetch('/api/devices')
      .then(res => res.json())
      .then(data => {
        if (data.devices) {
          data.devices.forEach(upsertDevice);
          updateCategoryPills();
          renderTable();
          updateMetrics();
          renderFilteredActivity();
        }
        if (data.tiers && data.tiers.discovery_running) setScanningState(true);
      })
      .catch(err => console.error('Failed to fetch initial devices:', err));
  }

  const ACTIVITY_MAX = 100;
  const FEED_TYPES = new Set(['alert', 'online', 'offline', 'found']);
  const recentFeedAt = new Map();
  let activityEventsList = [];
  let currentActivityFilter = 'all'; // 'all' | 'online' | 'offline'

  function formatFeedTime(isoStr) {
    if (!isoStr) return '';
    try {
      return new Date(isoStr).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
      return '';
    }
  }

  function getActivityStatus(ev) {
    const rule = ev.rule || '';
    const typ = ev.type || '';
    if (rule === 'device_online' || typ === 'online') return 'online';
    if (rule === 'device_offline' || typ === 'offline') return 'offline';
    if (rule === 'new_device' || typ === 'found') return 'found';
    if (typ === 'alert') return 'alert';
    return 'event';
  }

  function matchesActivityFilter(ev) {
    if (currentActivityFilter === 'all') return true;
    const st = getActivityStatus(ev);
    if (currentActivityFilter === 'online') {
      return st === 'online' || st === 'found';
    }
    if (currentActivityFilter === 'offline') {
      return st === 'offline';
    }
    return true;
  }

  function activityItemHTML(ev) {
    const typ = ev.type || ev.rule || 'event';
    const st = getActivityStatus(ev);
    const statusClass = `status-${st}`;
    const devId = ev.device_id || '';
    const dev = devId ? findDevice(devId) : null;
    const isClickable = !!dev;
    const titleAttr = isClickable ? `Click to inspect ${displayName(dev)}` : '';

    return `<li class="activity-item ${statusClass}${isClickable ? ' is-clickable' : ''}" data-type="${escapeHtml(typ)}" data-device-id="${escapeHtml(devId)}" ${titleAttr ? `title="${escapeHtml(titleAttr)}"` : ''}>
      <span class="act-time">
        <span class="act-dot"></span>
        ${escapeHtml(formatFeedTime(ev.timestamp))}
      </span>
      <span class="act-msg">${escapeHtml(ev.message || '')}</span>
      ${isClickable ? `<span class="act-hint">Inspect <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9 18 15 12 9 6"></polyline></svg></span>` : ''}
    </li>`;
  }

  function renderFilteredActivity() {
    if (!activityFeed) return;
    const filtered = activityEventsList.filter(matchesActivityFilter);
    if (!filtered.length) {
      const msg = currentActivityFilter === 'all'
        ? 'No recent activity'
        : `No recent ${currentActivityFilter} activity`;
      activityFeed.innerHTML = `<li class="activity-empty">${escapeHtml(msg)}</li>`;
      return;
    }
    activityFeed.innerHTML = filtered.slice(0, ACTIVITY_MAX).map(activityItemHTML).join('');
  }

  function prependActivity(ev) {
    if (!activityFeed || !ev || !ev.message) return;
    const key = ev.device_id || ev.message;
    const now = Date.now();
    const prev = recentFeedAt.get(key);
    if (prev && now - prev < 2000) return;
    recentFeedAt.set(key, now);

    activityEventsList.unshift(ev);
    if (activityEventsList.length > ACTIVITY_MAX * 2) {
      activityEventsList.pop();
    }
    renderFilteredActivity();
  }

  function renderActivity(events) {
    const list = (events || []).filter(ev => FEED_TYPES.has(ev.type));
    activityEventsList = list;
    renderFilteredActivity();
  }

  function fetchActivity() {
    fetch('/api/events/history?limit=100')
      .then(res => res.json())
      .then(data => renderActivity(data.events || []))
      .catch(err => console.error('Failed to fetch activity:', err));
  }

  function fetchSettings() {
    fetch('/api/settings')
      .then(res => res.json())
      .then(s => {
        if (alertsEnabledChk) alertsEnabledChk.checked = !!s.alerts_enabled;
        if (notifyMacosChk) notifyMacosChk.checked = !!s.notify_macos;
        if (alertOnlineChk) alertOnlineChk.checked = !!s.alert_online;
        if (alertOfflineChk) alertOfflineChk.checked = !!s.alert_offline;
        if (alertCooldownSel) {
          // Snap to the nearest offered preset so a value set via the API
          // (or clamped by the server) still shows something truthful.
          const want = Number(s.alert_cooldown_sec || 0);
          const opts = Array.from(alertCooldownSel.options).map(o => Number(o.value));
          const nearest = opts.reduce((a, b) =>
            Math.abs(b - want) < Math.abs(a - want) ? b : a, opts[0]);
          alertCooldownSel.value = String(nearest);
        }
        updateAlertToggleState();
      })
      .catch(err => console.error('Failed to fetch settings:', err));
  }

  function patchSettings(body) {
    fetch('/api/settings', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    }).catch(err => console.error('Failed to update settings:', err));
  }

  if (alertsEnabledChk) {
    alertsEnabledChk.addEventListener('change', () => {
      patchSettings({ alerts_enabled: alertsEnabledChk.checked });
    });
  }
  if (notifyMacosChk) {
    notifyMacosChk.addEventListener('change', () => {
      patchSettings({ notify_macos: notifyMacosChk.checked });
    });
  }

  // The per-rule toggles and the damping window only do anything while the
  // master Alerts switch is on, so reflect that rather than leaving dead
  // controls enabled.
  function updateAlertToggleState() {
    const on = !alertsEnabledChk || alertsEnabledChk.checked;
    [alertOnlineChk, alertOfflineChk, alertCooldownSel].forEach(el => {
      if (!el) return;
      el.disabled = !on;
      if (el.parentElement) el.parentElement.classList.toggle('is-disabled', !on);
    });
  }

  if (alertsEnabledChk) {
    alertsEnabledChk.addEventListener('change', updateAlertToggleState);
  }
  if (alertOnlineChk) {
    alertOnlineChk.addEventListener('change', () => {
      patchSettings({ alert_online: alertOnlineChk.checked });
    });
  }
  if (alertOfflineChk) {
    alertOfflineChk.addEventListener('change', () => {
      patchSettings({ alert_offline: alertOfflineChk.checked });
    });
  }
  if (alertCooldownSel) {
    alertCooldownSel.addEventListener('change', () => {
      patchSettings({ alert_cooldown_sec: Number(alertCooldownSel.value) });
    });
  }

  function recheckDevice() {
    if (!openDeviceId) return;
    const id = openDeviceId;
    btnRecheck.disabled = true;
    toolRecheckStatus.textContent = 'Checking ARP and probing…';
    if (toolRecheckOutput) toolRecheckOutput.hidden = true;

    fetch(`/api/devices/${encodeURIComponent(id)}/recheck`, { method: 'POST' })
      .then(res => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
      })
      .then(r => {
        // The drawer may have been closed or switched while the probe ran.
        if (openDeviceId !== id) return;
        const label = r.is_online ? 'Online' : 'Offline';
        const via = r.evidence === 'arp' ? 'Layer 2 (ARP)'
          : r.evidence === 'probe' ? 'active probe'
          : 'no response';
        toolRecheckStatus.textContent = `${label} — ${via}`;
        if (toolRecheckOutput) {
          toolRecheckOutput.textContent = r.message || '';
          toolRecheckOutput.hidden = !r.message;
        }
        if (r.device) {
          upsertDevice(r.device);
          renderTable();
          updateCategoryPills();
          updateMetrics();
        }
      })
      .catch(err => {
        if (openDeviceId !== id) return;
        toolRecheckStatus.textContent = `Check failed: ${err.message}`;
      })
      .finally(() => {
        if (btnRecheck) btnRecheck.disabled = false;
      });
  }

  function initSSE() {
    const eventSource = new EventSource('/api/events');

    eventSource.addEventListener('init', (e) => {
      const data = JSON.parse(e.data);
      if (data.devices) {
        devicesMap.clear();
        data.devices.forEach(upsertDevice);
        updateCategoryPills();
        renderTable();
        updateMetrics();
        renderFilteredActivity();
      }
    });

    eventSource.addEventListener('scan_start', (e) => {
      setScanningState(true);
      showProgress(0);
      try {
        const data = JSON.parse(e.data);
        if (data.network_key) {
          // Network may have changed; clear stale rows until scan_complete replaces inventory.
        }
      } catch (_) { /* ignore */ }
    });

    eventSource.addEventListener('network_changed', (e) => {
      const data = JSON.parse(e.data);
      replaceInventory(data.devices || []);
    });

    eventSource.addEventListener('scan_progress', (e) => {
      const prog = JSON.parse(e.data);
      if (prog.total > 0) showProgress(Math.round((prog.scanned / prog.total) * 100));
    });

    const onDeviceEvent = (e) => {
      const dev = JSON.parse(e.data);
      const id = deviceKey(dev);
      const prev = devicesMap.get(id);
      const cameOnline = prev && !prev.is_online && !!dev.is_online;
      upsertDevice(dev);
      updateCategoryPills();
      renderTable();
      updateMetrics();
      if (openDeviceId && id === openDeviceId) {
        fillDrawer(dev);
      }
      if (cameOnline && !(alertsEnabledChk && alertsEnabledChk.checked)) {
        prependActivity({
          type: 'online',
          device_id: id,
          message: `${displayName(dev)} is online`,
          timestamp: new Date().toISOString()
        });
      }
    };

    eventSource.addEventListener('device_found', (e) => {
      try {
        const dev = JSON.parse(e.data);
        if (!(alertsEnabledChk && alertsEnabledChk.checked)) {
          prependActivity({
            type: 'found',
            device_id: deviceKey(dev),
            message: `Discovered ${displayName(dev)} (${dev.ip || ''})`,
            timestamp: new Date().toISOString()
          });
        }
      } catch (_) { /* ignore */ }
      onDeviceEvent(e);
    });
    eventSource.addEventListener('device_updated', onDeviceEvent);
    eventSource.addEventListener('device_offline', (e) => {
      try {
        const dev = JSON.parse(e.data);
        if (!(alertsEnabledChk && alertsEnabledChk.checked)) {
          prependActivity({
            type: 'offline',
            device_id: deviceKey(dev),
            message: `${displayName(dev)} went offline`,
            timestamp: new Date().toISOString()
          });
        }
      } catch (_) { /* ignore */ }
      onDeviceEvent(e);
    });

    eventSource.addEventListener('alert', (e) => {
      try {
        const a = JSON.parse(e.data);
        prependActivity({
          type: 'alert',
          rule: a.rule,
          device_id: a.device_id,
          message: a.message,
          timestamp: a.timestamp
        });
      } catch (_) { /* ignore */ }
    });

    eventSource.addEventListener('portscan_complete', (e) => {
      const data = JSON.parse(e.data);
      const id = data.id;
      const dev = devicesMap.get(id);
      if (dev) {
        dev.open_ports = data.open_ports || [];
        upsertDevice(dev);
        if (openDeviceId === id) {
          renderPortsList(dev.open_ports);
          portsScanStatus.textContent = `Found ${(dev.open_ports || []).length} open port(s)`;
          portsScanStatus.className = 'tool-status ok';
          setPortsScanning(false);
        }
      }
    });

    eventSource.addEventListener('portscan_error', (e) => {
      const data = JSON.parse(e.data);
      if (openDeviceId === data.id) {
        portsScanStatus.textContent = data.error || 'Port scan failed';
        portsScanStatus.className = 'tool-status err';
        setPortsScanning(false);
      }
    });

    eventSource.addEventListener('scan_complete', (e) => {
      setScanningState(false);
      hideProgress();
      try {
        const data = JSON.parse(e.data);
        if (Array.isArray(data.devices)) {
          replaceInventory(data.devices);
        }
      } catch (_) { /* ignore */ }
    });

    eventSource.addEventListener('scan_error', (e) => {
      setScanningState(false);
      hideProgress();
      try {
        const msg = typeof e.data === 'string' ? e.data : (JSON.parse(e.data) || 'Scan failed');
        console.error('Scan error:', msg);
      } catch (_) {
        console.error('Scan error');
      }
    });
  }

  function replaceInventory(list) {
    devicesMap.clear();
    (list || []).forEach(upsertDevice);
    updateCategoryPills();
    renderTable();
    updateMetrics();
    if (openDeviceId && !devicesMap.has(openDeviceId)) {
      closeDrawer();
    } else if (openDeviceId) {
      fillDrawer(devicesMap.get(openDeviceId));
    }
  }

  function triggerScan() {
    setScanningState(true);
    fetch('/api/scan', { method: 'POST' })
      .catch(err => {
        console.error('Failed to trigger scan:', err);
        setScanningState(false);
      });
  }

  function setScanningState(isScanning) {
    if (isScanning) {
      rescanBtn.classList.add('scanning');
      scanBtnText.textContent = 'Scanning...';
      rescanBtn.disabled = true;
    } else {
      rescanBtn.classList.remove('scanning');
      scanBtnText.textContent = 'Scan Network';
      rescanBtn.disabled = false;
    }
  }

  function showProgress(_pct) {
    // Progress bar is unreliable for now — keep it hidden.
    if (progressContainer) progressContainer.style.display = 'none';
  }

  function hideProgress() {
    if (progressContainer) progressContainer.style.display = 'none';
    if (progressBarFill) progressBarFill.style.width = '0%';
  }

  function updateMetrics() {
    const devices = Array.from(devicesMap.values());
    statTotalEl.textContent = devices.length;
    statOnlineEl.textContent = devices.filter(d => d.is_online).length;
    statOfflineEl.textContent = devices.filter(d => !d.is_online).length;
  }

  function updateCategoryPills() {
    const devices = Array.from(devicesMap.values());
    const typeCounts = new Map();
    let onlineCount = 0;
    devices.forEach(d => {
      if (d.is_online) onlineCount++;
      const t = displayType(d);
      typeCounts.set(t, (typeCounts.get(t) || 0) + 1);
    });

    const categories = [
      { id: 'all', label: `All Devices (${devices.length})` },
      { id: 'online', label: `Online (${onlineCount})` }
    ];
    Array.from(typeCounts.entries()).sort((a, b) => b[1] - a[1]).forEach(([type, count]) => {
      categories.push({ id: type, label: `${type} (${count})` });
    });

    categoryPillsContainer.innerHTML = categories.map(cat => {
      const activeClass = (cat.id === currentCategory) ? 'active' : '';
      return `<button class="pill ${activeClass}" data-category="${escapeHtml(cat.id)}">${escapeHtml(cat.label)}</button>`;
    }).join('');
  }

  function renderTable() {
    const devices = Array.from(devicesMap.values());
    const filtered = devices.filter(dev => {
      if (currentCategory === 'online' && !dev.is_online) return false;
      if (currentCategory !== 'all' && currentCategory !== 'online' && displayType(dev) !== currentCategory) return false;
      if (searchQuery) {
        const haystack = `${displayName(dev)} ${dev.hostname || ''} ${dev.ip} ${dev.mac || ''} ${dev.vendor || ''} ${dev.model || ''} ${displayType(dev)} ${dev.note || ''}`.toLowerCase();
        if (!haystack.includes(searchQuery)) return false;
      }
      return true;
    });

    if (filtered.length === 0) {
      deviceTableBody.innerHTML = `
        <tr class="empty-row">
          <td colspan="7" style="text-align:center; padding:30px; color:var(--text-muted);">
            No devices found matching current filters.
          </td>
        </tr>`;
      return;
    }

    deviceTableBody.innerHTML = filtered.map(dev => {
      const key = deviceKey(dev);
      const statusBadge = dev.is_online
        ? `<span class="status-badge online"><span class="pulse-dot"></span> Online</span>`
        : `<span class="status-badge offline">Offline</span>`;
      const latencyStr = dev.latency_ms > 0 ? `${dev.latency_ms.toFixed(1)} ms` : '—';

      return `
        <tr data-id="${escapeHtml(key)}">
          <td>
            <div class="device-type-cell">
              <div class="device-icon-badge">${getDeviceSVGIcon(dev)}</div>
              <span>${escapeHtml(displayType(dev))}</span>
            </div>
          </td>
          <td><div class="device-title">${escapeHtml(displayName(dev))}</div></td>
          <td>
            <div>${escapeHtml(dev.vendor || 'Generic')}</div>
            <div style="font-size:12px; color:var(--text-dim);">${escapeHtml(dev.model || '')}</div>
          </td>
          <td>
            ${statusBadge}
            <div style="font-size:11px; color:var(--text-dim); margin-top:2px;">${latencyStr}</div>
          </td>
          <td class="font-mono">${escapeHtml(dev.ip)}</td>
          <td class="font-mono">${escapeHtml(dev.mac || '—')}</td>
          <td>
            <button class="btn-sm inspect-btn" data-id="${escapeHtml(key)}">Inspect</button>
          </td>
        </tr>`;
    }).join('');

    document.querySelectorAll('.inspect-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        openDrawer(btn.dataset.id);
      });
    });
    document.querySelectorAll('#deviceTableBody tr[data-id]').forEach(tr => {
      tr.addEventListener('click', () => openDrawer(tr.dataset.id));
    });
  }

  function setActiveTab(tab) {
    activeTab = tab;
    document.querySelectorAll('.drawer-tab').forEach(t => {
      t.classList.toggle('active', t.dataset.tab === tab);
    });
    document.querySelectorAll('.drawer-tab-panel').forEach(p => {
      p.classList.toggle('active', p.id === `tab-${tab}`);
    });
    if (tab === 'history' && openDeviceId) loadHistory(openDeviceId);
    if (tab === 'ports' && openDeviceId) {
      const dev = devicesMap.get(openDeviceId);
      if (dev) renderPortsList(dev.open_ports);
    }
  }

  function openDrawer(id, targetTab) {
    const dev = findDevice(id);
    if (!dev) return;
    openDeviceId = dev.id || id;
    saveStatus.textContent = '';
    if (toolRecheckStatus) toolRecheckStatus.textContent = '';
    if (toolRecheckOutput) {
      toolRecheckOutput.hidden = true;
      toolRecheckOutput.textContent = '';
    }
    toolResolveStatus.textContent = '';
    toolResolveStatus.className = 'tool-status';
    toolResolveOutput.hidden = true;
    toolResolveOutput.textContent = '';
    if (toolProbeStatus) {
      toolProbeStatus.textContent = '';
      toolProbeStatus.className = 'tool-status';
    }
    if (toolProbeCard) {
      toolProbeCard.hidden = true;
      toolProbeCard.innerHTML = '';
    }
    portsScanStatus.textContent = '';
    portsScanStatus.className = 'tool-status';
    setPortsScanning(false);
    setActiveTab(targetTab || (activeTab === 'history' ? 'history' : 'overview'));
    fillDrawer(dev);
    deviceDrawer.classList.add('open');
    document.body.classList.add('drawer-open');
    if (activeTab === 'history') loadHistory(dev.id || id);
  }

  function closeDrawer() {
    deviceDrawer.classList.remove('open');
    document.body.classList.remove('drawer-open');
    openDeviceId = null;
  }

  function fillDrawer(dev) {
    drawerTypeIcon.innerHTML = getDeviceSVGIcon(dev, 32);
    drawerDeviceName.textContent = displayName(dev);
    drawerDeviceSub.textContent = `${displayType(dev)} • ${dev.vendor || 'Unknown Vendor'}`;

    editCustomName.value = dev.custom_name || '';
    editTypeOverride.value = dev.device_type_override || '';
    editNote.value = dev.note || '';

    drawerIP.textContent = dev.ip;
    drawerMAC.textContent = dev.mac || 'Unspecified';
    drawerVendor.textContent = dev.vendor || 'Generic Device';
    drawerModel.textContent = dev.model || displayType(dev) || 'Standard Network Hardware';
    const nameSourceEl = document.getElementById('drawerNameSource');
    if (nameSourceEl) {
      nameSourceEl.textContent = formatNameSource(dev.name_source);
    }
    drawerLatency.textContent = dev.is_online
      ? (dev.latency_ms > 0 ? `${dev.latency_ms.toFixed(2)} ms` : '< 1 ms')
      : 'Offline';
    drawerStatus.textContent = dev.is_online ? 'Active / Responding' : 'Offline / Inactive';
    drawerFirstSeen.textContent = formatDate(dev.first_seen);
    drawerLastSeen.textContent = formatDate(dev.last_seen);

    let tagsHtml = `<span class="tag">ICMP Ping</span>`;
    if (dev.mac) tagsHtml += `<span class="tag">ARP Cache</span>`;
    if (dev.hostname) tagsHtml += `<span class="tag">mDNS / Reverse DNS</span>`;
    if (dev.services && dev.services.length > 0) {
      dev.services.forEach(s => { tagsHtml += `<span class="tag">${escapeHtml(s)}</span>`; });
    }
    drawerServices.innerHTML = tagsHtml;
    renderPortsList(dev.open_ports);
  }

  function renderPortsList(openPorts) {
    const ports = openPorts || [];
    if (!ports.length) {
      portsList.innerHTML = `<div class="drawer-empty"><p>No open ports recorded</p></div>`;
      return;
    }
    portsList.innerHTML = ports.map(p => `
      <div class="port-row">
        <span class="port-num">${escapeHtml(String(p.port))}</span>
        <span class="port-name">${escapeHtml(p.name || '')}</span>
      </div>
    `).join('');
  }

  function setPortsScanning(busy) {
    btnScanPorts.disabled = busy;
    btnScanPortsDeep.disabled = busy;
  }

  function startPortScan(mode) {
    if (!openDeviceId) return;
    const id = openDeviceId;
    setPortsScanning(true);
    portsScanStatus.className = 'tool-status';
    portsScanStatus.textContent = mode === 'deep'
      ? 'Deep scanning ports 1–1024…'
      : 'Scanning common ports…';

    const q = mode === 'deep' ? '?mode=deep' : '?mode=common';
    fetch(`/api/devices/${encodeURIComponent(id)}/portscan${q}`, { method: 'POST' })
      .then(res => {
        if (!res.ok) throw new Error('port scan failed');
        return res.json();
      })
      .then(data => {
        if (data.status === 'already_running') {
          portsScanStatus.textContent = 'Scan already running…';
          return;
        }
        // Results arrive via SSE portscan_complete / portscan_error.
        // Keep a long safety timeout only if SSE is dropped.
        setTimeout(() => {
          if (btnScanPorts.disabled && openDeviceId === id) {
            const dev = devicesMap.get(id);
            if (dev && dev.open_ports) renderPortsList(dev.open_ports);
            setPortsScanning(false);
            if (portsScanStatus.textContent.includes('Scanning') || portsScanStatus.textContent.includes('Deep')) {
              portsScanStatus.textContent = 'Scan finished (refresh if ports missing)';
            }
          }
        }, mode === 'deep' ? 45000 : 15000);
      })
      .catch(err => {
        console.error(err);
        portsScanStatus.textContent = 'Port scan failed';
        portsScanStatus.className = 'tool-status err';
        setPortsScanning(false);
      });
  }

  function saveDeviceEdits() {
    if (!openDeviceId) return;
    const id = openDeviceId;
    saveStatus.textContent = 'Saving…';
    fetch(`/api/devices/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        custom_name: editCustomName.value.trim(),
        note: editNote.value.trim(),
        device_type_override: editTypeOverride.value.trim()
      })
    })
      .then(res => {
        if (!res.ok) throw new Error('save failed');
        return res.json();
      })
      .then(dev => {
        upsertDevice(dev);
        updateCategoryPills();
        renderTable();
        saveStatus.textContent = 'Saved';
        setTimeout(() => { if (saveStatus.textContent === 'Saved') saveStatus.textContent = ''; }, 2000);
      })
      .catch(err => {
        console.error(err);
        saveStatus.textContent = 'Error saving';
      });
  }

  function loadHistory(id) {
    historyList.innerHTML = `<div class="drawer-empty"><p>Loading…</p></div>`;
    fetch(`/api/devices/${encodeURIComponent(id)}/history?limit=50`)
      .then(res => {
        if (!res.ok) throw new Error('history failed');
        return res.json();
      })
      .then(data => {
        const events = data.events || [];
        if (!events.length) {
          historyList.innerHTML = `<div class="drawer-empty"><p>No history yet</p></div>`;
          return;
        }
        historyList.innerHTML = events.map(ev => `
          <div class="history-item">
            <div class="hist-type">${escapeHtml(ev.type || 'event')}</div>
            <div class="hist-msg">${escapeHtml(ev.message || '')}</div>
            <div class="hist-time">${formatDate(ev.timestamp)}</div>
          </div>
        `).join('');
      })
      .catch(() => {
        historyList.innerHTML = `<div class="drawer-empty"><p>Failed to load history</p></div>`;
      });
  }

  function resolveDeviceName() {
    if (!openDeviceId) return;
    const id = openDeviceId;
    btnResolveName.disabled = true;
    toolResolveStatus.className = 'tool-status';
    toolResolveStatus.textContent = 'Looking up Bonjour / DNS…';
    toolResolveOutput.hidden = true;

    fetch(`/api/devices/${encodeURIComponent(id)}/resolve-name`, { method: 'POST' })
      .then(res => {
        if (!res.ok) throw new Error('resolve failed');
        return res.json();
      })
      .then(data => {
        if (data.device) {
          upsertDevice(data.device);
          updateCategoryPills();
          renderTable();
          if (openDeviceId === id) fillDrawer(data.device);
        }
        const msg = data.message
          || (data.changed ? `Resolved to ${data.hostname}` : (data.found ? 'Name unchanged' : 'No name found'));
        toolResolveStatus.textContent = msg;
        toolResolveStatus.className = data.found ? 'tool-status ok' : 'tool-status err';

        const lines = [];
        if (data.hostname) {
          lines.push(`${data.hostname}  (${formatNameSource(data.name_source)})`);
        }
        (data.candidates || []).forEach(c => {
          lines.push(`· ${c.hostname}  [${formatNameSource(c.source)}]`);
        });
        if (lines.length) {
          toolResolveOutput.textContent = lines.join('\n');
          toolResolveOutput.hidden = false;
        }
      })
      .catch(err => {
        console.error(err);
        toolResolveStatus.textContent = 'Resolve failed';
        toolResolveStatus.className = 'tool-status err';
      })
      .finally(() => {
        btnResolveName.disabled = false;
      });
  }

  function runDeepProbe() {
    if (!openDeviceId) return;
    const id = openDeviceId;
    if (btnDeepProbe) btnDeepProbe.disabled = true;
    if (toolProbeStatus) {
      toolProbeStatus.className = 'tool-status';
      toolProbeStatus.textContent = 'Probing UPnP, NetBIOS, and TLS…';
    }
    if (toolProbeCard) toolProbeCard.hidden = true;

    fetch(`/api/devices/${encodeURIComponent(id)}/probe`, { method: 'POST' })
      .then(res => {
        if (!res.ok) throw new Error('probe failed');
        return res.json();
      })
      .then(data => {
        if (data.device) {
          upsertDevice(data.device);
          updateCategoryPills();
          renderTable();
          if (openDeviceId === id) fillDrawer(data.device);
        }
        const pr = data.probe || {};
        const hasFindings = !!(pr.upnp || pr.netbios || pr.tls);

        if (toolProbeStatus) {
          toolProbeStatus.textContent = hasFindings
            ? 'Deep fingerprint complete — device attributes updated'
            : 'Probe complete — no responsive UPnP, NetBIOS, or TLS services';
          toolProbeStatus.className = hasFindings ? 'tool-status ok' : 'tool-status';
        }

        if (toolProbeCard) {
          let html = '';

          if (pr.upnp) {
            html += `<div class="probe-group">
              <div class="probe-group-header">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
                UPnP / SSDP Descriptor
              </div>
              <div class="probe-grid">`;
            if (pr.upnp.model_name) html += `<span class="probe-key">Model:</span><span class="probe-val font-mono">${escapeHtml(pr.upnp.model_name)}</span>`;
            if (pr.upnp.model_number) html += `<span class="probe-key">Model Number:</span><span class="probe-val font-mono">${escapeHtml(pr.upnp.model_number)}</span>`;
            if (pr.upnp.manufacturer) html += `<span class="probe-key">Manufacturer:</span><span class="probe-val">${escapeHtml(pr.upnp.manufacturer)}</span>`;
            if (pr.upnp.friendly_name) html += `<span class="probe-key">Friendly Name:</span><span class="probe-val">${escapeHtml(pr.upnp.friendly_name)}</span>`;
            if (pr.upnp.presentation_url) {
              html += `<span class="probe-key">Web Console:</span><span class="probe-val"><a class="probe-link font-mono" href="${escapeHtml(pr.upnp.presentation_url)}" target="_blank" rel="noopener">${escapeHtml(pr.upnp.presentation_url)}</a></span>`;
            }
            html += `</div></div>`;
          }

          if (pr.netbios) {
            html += `<div class="probe-group">
              <div class="probe-group-header">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
                NetBIOS Name Service
              </div>
              <div class="probe-grid">`;
            if (pr.netbios.computer_name) html += `<span class="probe-key">Computer:</span><span class="probe-val font-mono">${escapeHtml(pr.netbios.computer_name)}</span>`;
            if (pr.netbios.workgroup) html += `<span class="probe-key">Workgroup:</span><span class="probe-val font-mono">${escapeHtml(pr.netbios.workgroup)}</span>`;
            if (pr.netbios.user_name) html += `<span class="probe-key">User:</span><span class="probe-val font-mono">${escapeHtml(pr.netbios.user_name)}</span>`;
            if (pr.netbios.mac) html += `<span class="probe-key">Reported MAC:</span><span class="probe-val font-mono">${escapeHtml(pr.netbios.mac)}</span>`;
            html += `</div></div>`;
          }

          if (pr.tls) {
            html += `<div class="probe-group">
              <div class="probe-group-header">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                TLS Certificate (Port ${pr.tls.port})
              </div>
              <div class="probe-grid">`;
            if (pr.tls.subject_cn) html += `<span class="probe-key">Common Name:</span><span class="probe-val font-mono">${escapeHtml(pr.tls.subject_cn)}</span>`;
            if (pr.tls.issuer_org) html += `<span class="probe-key">Issuer:</span><span class="probe-val">${escapeHtml(pr.tls.issuer_org)}</span>`;
            if (pr.tls.sans && pr.tls.sans.length) html += `<span class="probe-key">Alt Names:</span><span class="probe-val font-mono">${escapeHtml(pr.tls.sans.join(', '))}</span>`;
            html += `</div></div>`;
          }

          if (html) {
            toolProbeCard.innerHTML = html;
            toolProbeCard.hidden = false;
          }
        }
      })
      .catch(err => {
        console.error('Deep probe failed:', err);
        if (toolProbeStatus) {
          toolProbeStatus.textContent = 'Probe request failed';
          toolProbeStatus.className = 'tool-status err';
        }
      })
      .finally(() => {
        if (btnDeepProbe) btnDeepProbe.disabled = false;
      });
  }

  const simpleIconSlugs = {
    "apple, inc.": "apple",
    "raspberry pi trading ltd": "raspberrypi",
    "raspberry pi foundation": "raspberrypi",
    "eero (amazon)": "eero",
    "google / nest": "googlehome",
    "google, inc.": "google",
    "amazon / ring": "ring",
    "amazon technologies": "amazon",
    "sonos, inc.": "sonos",
    "samsung electronics": "samsung",
    "nintendo co., ltd.": "nintendo",
    "sony corporation": "sony",
    "sony interactive entertainment": "playstation",
    "microsoft corporation": "microsoft",
    "hyper-v / microsoft": "microsoft",
    "roku, inc.": "roku",
    "ubiquiti inc.": "ubiquiti",
    "tp-link technologies": "tplink",
    "netgear": "netgear",
    "cisco systems": "cisco",
    "hp inc.": "hp",
    "lg electronics": "lg",
    "intel corporation": "intel",
    "espressif inc.": "espressif",
    "philips lighting / hue": "philipshue",
    "oracle virtualbox": "virtualbox"
  };

  function getDeviceSVGIcon(dev, size = 20) {
    const vendorLower = (dev.vendor || '').toLowerCase();
    const slug = simpleIconSlugs[vendorLower];
    if (slug) {
      const icon = escapeHtml(dev.icon || '');
      const dtype = escapeHtml(displayType(dev));
      const alt = escapeHtml(dev.vendor || '');
      return `<img class="simple-icon" src="https://cdn.jsdelivr.net/npm/simple-icons@v11/icons/${slug}.svg" width="${size}" height="${size}" alt="${alt}" onerror="this.outerHTML=getCategorySVG('${icon}', '${dtype}', ${size})" />`;
    }
    return getCategorySVG(dev.icon, displayType(dev), size);
  }

  window.getCategorySVG = function getCategorySVG(icon, devType, size = 20) {
    const s = size;
    if (icon === 'router' || devType === 'Router') {
      return `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 13a10 10 0 0 1 14 0"/><path d="M8.5 16.5a5 5 0 0 1 7 0"/><path d="M2 8.5a15 15 0 0 1 20 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>`;
    }
    if (icon === 'laptop' || devType === 'Computer' || devType === 'Laptop') {
      return `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="2" y1="20" x2="22" y2="20"/></svg>`;
    }
    if (icon === 'smartphone' || devType === 'Mobile Phone') {
      return `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="2" width="14" height="20" rx="2" ry="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>`;
    }
    if (icon === 'tablet' || devType === 'Tablet') {
      return `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="2" width="16" height="20" rx="2" ry="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>`;
    }
    if (icon === 'tv' || devType === 'Smart TV') {
      return `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="7" width="20" height="13" rx="2" ry="2"/><polyline points="17 2 12 7 7 2"/></svg>`;
    }
    if (icon === 'speaker' || devType === 'Smart Speaker') {
      return `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="2" width="16" height="20" rx="2" ry="2"/><circle cx="12" cy="14" r="4"/><line x1="12" y1="6" x2="12.01" y2="6"/></svg>`;
    }
    if (icon === 'printer' || devType === 'Printer') {
      return `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>`;
    }
    if (icon === 'gamepad' || devType === 'Game Console') {
      return `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="6" y1="12" x2="10" y2="12"/><line x1="8" y1="10" x2="8" y2="14"/><circle cx="15" cy="11" r="1"/><circle cx="17" cy="13" r="1"/><path d="M17.8 2a2 2 0 0 1 1.4.6l2.2 2.2a2 2 0 0 1 .6 1.4v11.6a2 2 0 0 1-.6 1.4l-2.2 2.2a2 2 0 0 1-1.4.6H6.2a2 2 0 0 1-1.4-.6L2.6 19.2a2 2 0 0 1-.6-1.4V6.2a2 2 0 0 1 .6-1.4L4.8 2.6A2 2 0 0 1 6.2 2h11.6z"/></svg>`;
    }
    if (icon === 'cpu' || devType === 'SBC / Server') {
      return `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="15" x2="23" y2="15"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="15" x2="4" y2="15"/></svg>`;
    }
    return `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>`;
  };

  function formatDate(isoStr) {
    if (!isoStr) return 'Just now';
    try {
      const d = new Date(isoStr);
      return d.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
      return 'Just now';
    }
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/[&<>"']/g, m => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;'
    }[m]));
  }
});
