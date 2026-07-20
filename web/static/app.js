// Gofing - Real-Time Dashboard Client Logic with Simple Icons integration
document.addEventListener('DOMContentLoaded', () => {
  let devicesMap = new Map();
  let currentCategory = 'all';
  let searchQuery = '';

  // Elements
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

  // Modal elements
  const deviceModal = document.getElementById('deviceModal');
  const modalCloseBtn = document.getElementById('modalCloseBtn');
  const modalTypeIcon = document.getElementById('modalTypeIcon');
  const modalDeviceName = document.getElementById('modalDeviceName');
  const modalDeviceSub = document.getElementById('modalDeviceSub');
  const modalIP = document.getElementById('modalIP');
  const modalMAC = document.getElementById('modalMAC');
  const modalVendor = document.getElementById('modalVendor');
  const modalModel = document.getElementById('modalModel');
  const modalLatency = document.getElementById('modalLatency');
  const modalStatus = document.getElementById('modalStatus');
  const modalFirstSeen = document.getElementById('modalFirstSeen');
  const modalLastSeen = document.getElementById('modalLastSeen');
  const modalServices = document.getElementById('modalServices');

  const copyIPBtn = document.getElementById('copyIPBtn');
  const copyMACBtn = document.getElementById('copyMACBtn');

  copyIPBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    const text = modalIP.textContent;
    if (text && text !== '—') {
      copyToClipboard(text, copyIPBtn);
    }
  });

  copyMACBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    const text = modalMAC.textContent;
    if (text && text !== '—' && text !== 'Unspecified') {
      copyToClipboard(text, copyMACBtn);
    }
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
    }).catch(err => {
      console.error('Clipboard copy error:', err);
    });
  }

  // Initialize
  fetchNetworkInfo();
  fetchInitialDevices();
  initSSE();

  // Search input handler
  searchInput.addEventListener('input', (e) => {
    searchQuery = e.target.value.toLowerCase().trim();
    renderTable();
  });

  // Category Pills handler
  document.getElementById('categoryPills').addEventListener('click', (e) => {
    if (e.target.classList.contains('pill')) {
      document.querySelectorAll('.pill').forEach(p => p.classList.remove('active'));
      e.target.classList.add('active');
      currentCategory = e.target.dataset.category;
      renderTable();
    }
  });

  // Trigger scan button
  rescanBtn.addEventListener('click', () => {
    triggerScan();
  });

  // Close modal
  modalCloseBtn.addEventListener('click', () => {
    deviceModal.classList.remove('open');
  });

  deviceModal.addEventListener('click', (e) => {
    if (e.target === deviceModal) {
      deviceModal.classList.remove('open');
    }
  });

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
          data.devices.forEach(dev => devicesMap.set(dev.ip, dev));
          renderTable();
          updateMetrics();
        }
        if (data.is_scanning) {
          setScanningState(true);
        }
      })
      .catch(err => console.error('Failed to fetch initial devices:', err));
  }

  function initSSE() {
    const eventSource = new EventSource('/api/events');

    eventSource.addEventListener('init', (e) => {
      const data = JSON.parse(e.data);
      if (data.devices) {
        data.devices.forEach(dev => devicesMap.set(dev.ip, dev));
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
      if (prog.total > 0) {
        const pct = Math.round((prog.scanned / prog.total) * 100);
        showProgress(pct);
      }
    });

    eventSource.addEventListener('device_found', (e) => {
      const dev = JSON.parse(e.data);
      devicesMap.set(dev.ip, dev);
      renderTable();
      updateMetrics();
    });

    eventSource.addEventListener('device_updated', (e) => {
      const dev = JSON.parse(e.data);
      devicesMap.set(dev.ip, dev);
      renderTable();
      updateMetrics();
    });

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
    const total = devices.length;
    const online = devices.filter(d => d.is_online).length;
    const offline = total - online;

    statTotalEl.textContent = total;
    statOnlineEl.textContent = online;
    statOfflineEl.textContent = offline;
  }

  function renderTable() {
    const devices = Array.from(devicesMap.values());

    const filtered = devices.filter(dev => {
      if (currentCategory === 'online' && !dev.is_online) return false;
      if (currentCategory === 'router' && dev.device_type !== 'Router') return false;
      if (currentCategory === 'computer' && dev.device_type !== 'Computer') return false;
      if (currentCategory === 'mobile' && !['Mobile Phone', 'Tablet', 'Smartwatch'].includes(dev.device_type)) return false;
      if (currentCategory === 'tv' && dev.device_type !== 'Smart TV') return false;
      if (currentCategory === 'speaker' && dev.device_type !== 'Smart Speaker') return false;
      if (currentCategory === 'printer' && dev.device_type !== 'Printer') return false;
      if (currentCategory === 'iot' && dev.device_type !== 'Smart Home / IoT') return false;

      if (searchQuery) {
        const haystack = `${dev.hostname} ${dev.ip} ${dev.mac} ${dev.vendor} ${dev.model} ${dev.device_type}`.toLowerCase();
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
        </tr>
      `;
      return;
    }

    deviceTableBody.innerHTML = filtered.map(dev => {
      const iconMarkup = getDeviceSVGIcon(dev);
      const name = dev.hostname || dev.model || dev.vendor || 'Discovered Device';
      const statusBadge = dev.is_online
        ? `<span class="status-badge online"><span class="pulse-dot"></span> Online</span>`
        : `<span class="status-badge offline">Offline</span>`;

      const latencyStr = dev.latency_ms > 0 ? `${dev.latency_ms.toFixed(1)} ms` : '—';

      return `
        <tr data-ip="${dev.ip}">
          <td>
            <div class="device-type-cell">
              <div class="device-icon-badge">${iconMarkup}</div>
              <span>${dev.device_type || 'Device'}</span>
            </div>
          </td>
          <td>
            <div class="device-title">${escapeHtml(name)}</div>
          </td>
          <td>
            <div>${escapeHtml(dev.vendor || 'Generic')}</div>
            <div style="font-size:12px; color:var(--text-dim);">${escapeHtml(dev.model || '')}</div>
          </td>
          <td>
            ${statusBadge}
            <div style="font-size:11px; color:var(--text-dim); margin-top:2px;">${latencyStr}</div>
          </td>
          <td class="font-mono">${dev.ip}</td>
          <td class="font-mono">${dev.mac || '—'}</td>
          <td>
            <button class="btn-sm inspect-btn" data-ip="${dev.ip}">Inspect</button>
          </td>
        </tr>
      `;
    }).join('');

    // Attach row click listeners
    document.querySelectorAll('.inspect-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        openModal(btn.dataset.ip);
      });
    });

    document.querySelectorAll('#deviceTableBody tr[data-ip]').forEach(tr => {
      tr.addEventListener('click', () => {
        openModal(tr.dataset.ip);
      });
    });
  }

  function openModal(ip) {
    const dev = devicesMap.get(ip);
    if (!dev) return;

    modalTypeIcon.innerHTML = getDeviceSVGIcon(dev, 32);
    modalDeviceName.textContent = dev.hostname || dev.model || dev.vendor || 'Network Device';
    modalDeviceSub.textContent = `${dev.device_type || 'Generic Device'} • ${dev.vendor || 'Unknown Vendor'}`;

    modalIP.textContent = dev.ip;
    modalMAC.textContent = dev.mac || 'Unspecified';
    modalVendor.textContent = dev.vendor || 'Generic Device';
    modalModel.textContent = dev.model || dev.device_type || 'Standard Network Hardware';
    modalLatency.textContent = dev.is_online ? (dev.latency_ms > 0 ? `${dev.latency_ms.toFixed(2)} ms` : '< 1 ms') : 'Offline';
    modalStatus.textContent = dev.is_online ? 'Active / Responding' : 'Offline / Inactive';

    modalFirstSeen.textContent = formatDate(dev.first_seen);
    modalLastSeen.textContent = formatDate(dev.last_seen);

    // Tags
    let tagsHtml = `<span class="tag">ICMP Ping</span>`;
    if (dev.mac) tagsHtml += `<span class="tag">ARP Cache</span>`;
    if (dev.hostname) tagsHtml += `<span class="tag">mDNS / Reverse DNS</span>`;
    if (dev.services && dev.services.length > 0) {
      dev.services.forEach(s => {
        tagsHtml += `<span class="tag">${escapeHtml(s)}</span>`;
      });
    }

    modalServices.innerHTML = tagsHtml;
    deviceModal.classList.add('open');
  }

  // Simple Icons brand slug mapping & fallback vector SVGs
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
      // Return Simple Icons SVG via CDN image or inline template
      return `<img class="simple-icon" src="https://cdn.jsdelivr.net/npm/simple-icons@v11/icons/${slug}.svg" width="${size}" height="${size}" alt="${dev.vendor}" onerror="this.outerHTML=getCategorySVG('${dev.icon}', '${dev.device_type}', ${size})" />`;
    }

    return getCategorySVG(dev.icon, dev.device_type, size);
  }

  function getCategorySVG(icon, devType, size = 20) {
    const s = size;
    if (icon === 'router' || devType === 'Router') {
      return `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 13a10 10 0 0 1 14 0"/><path d="M8.5 16.5a5 5 0 0 1 7 0"/><path d="M2 8.5a15 15 0 0 1 20 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>`;
    }
    if (icon === 'laptop' || devType === 'Computer') {
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

    // Default network device icon
    return `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>`;
  }

  function formatDate(isoStr) {
    if (!isoStr) return 'Just now';
    try {
      const d = new Date(isoStr);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
      return 'Just now';
    }
  }

  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/[&<>"']/g, m => {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[m];
    });
  }
});
