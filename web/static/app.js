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
  const progressContainer = document.getElementById('progressContainer');
  const progressBarFill = document.getElementById('progressBarFill');
  const categoryPillsContainer = document.getElementById('categoryPills');

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

  fetchNetworkInfo();
  fetchInitialDevices();
  initSSE();

  searchInput.addEventListener('input', (e) => {
    searchQuery = e.target.value.toLowerCase().trim();
    renderTable();
  });

  categoryPillsContainer.addEventListener('click', (e) => {
    const pill = e.target.closest('.pill');
    if (pill) {
      document.querySelectorAll('.pill').forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      currentCategory = pill.dataset.category;
      renderTable();
    }
  });

  rescanBtn.addEventListener('click', () => triggerScan());

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

  function deviceKey(dev) {
    return dev.id || (dev.mac ? dev.mac : `ip:${dev.ip}`);
  }

  function displayName(dev) {
    return dev.custom_name || dev.hostname || dev.model || dev.vendor || 'Discovered Device';
  }

  function displayType(dev) {
    return dev.device_type_override || dev.device_type || 'Generic Device';
  }

  function upsertDevice(dev) {
    const key = deviceKey(dev);
    // Drop stale IP-only keys if ID is now available
    if (dev.id) {
      for (const [k, v] of devicesMap.entries()) {
        if (k !== key && v.ip === dev.ip && (!v.id || v.id === dev.id)) {
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
        }
        if (data.is_scanning) setScanningState(true);
      })
      .catch(err => console.error('Failed to fetch initial devices:', err));
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
      }
    });

    eventSource.addEventListener('scan_start', () => {
      setScanningState(true);
      showProgress(0);
    });

    eventSource.addEventListener('scan_progress', (e) => {
      const prog = JSON.parse(e.data);
      if (prog.total > 0) showProgress(Math.round((prog.scanned / prog.total) * 100));
    });

    const onDeviceEvent = (e) => {
      const dev = JSON.parse(e.data);
      upsertDevice(dev);
      updateCategoryPills();
      renderTable();
      updateMetrics();
    };

    eventSource.addEventListener('device_found', onDeviceEvent);
    eventSource.addEventListener('device_updated', onDeviceEvent);
    eventSource.addEventListener('device_offline', onDeviceEvent);

    eventSource.addEventListener('scan_complete', () => {
      setScanningState(false);
      hideProgress();
    });
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

  function showProgress(pct) {
    progressContainer.style.display = 'block';
    progressBarFill.style.width = `${pct}%`;
  }

  function hideProgress() {
    progressBarFill.style.width = '100%';
    setTimeout(() => {
      progressContainer.style.display = 'none';
      progressBarFill.style.width = '0%';
    }, 500);
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
  }

  function openDrawer(id) {
    const dev = devicesMap.get(id);
    if (!dev) return;
    openDeviceId = id;
    saveStatus.textContent = '';
    setActiveTab(activeTab === 'history' ? 'history' : 'overview');
    fillDrawer(dev);
    deviceDrawer.classList.add('open');
    if (activeTab === 'history') loadHistory(id);
  }

  function closeDrawer() {
    deviceDrawer.classList.remove('open');
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
      return `<img class="simple-icon" src="https://cdn.jsdelivr.net/npm/simple-icons@v11/icons/${slug}.svg" width="${size}" height="${size}" alt="${escapeHtml(dev.vendor)}" onerror="this.outerHTML=getCategorySVG('${dev.icon}', '${dev.device_type}', ${size})" />`;
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
