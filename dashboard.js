// Load devices on page load
document.addEventListener('DOMContentLoaded', () => {
    loadDevices();
    updateStats();
});

// Load devices from backend
async function loadDevices() {
    try {
        const response = await fetch(`${API_URL}/devices.json`);
        devices = await response.json();
        renderDevices();
        updateStats();
    } catch (error) {
        console.error('Error loading devices:', error);
        showNotification('Error loading devices', 'error');
    }
}

// Render devices table
function renderDevices() {
    const tbody = document.getElementById('deviceList');
    if (!devices || devices.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4">No devices enrolled</td></tr>';
        return;
    }
    
    tbody.innerHTML = devices.map(device => `
        <tr>
            <td>${device.name}</td>
            <td>
                <span class="status-badge status-${device.status}">
                    ${device.status}
                </span>
            </td>
            <td>${new Date(device.lastSeen).toLocaleString()}</td>
            <td>
                ${device.status === 'active' ? 
                    `<button onclick="lockDevice('${device.id}')">🔒 Lock</button>` : 
                    `<button onclick="unlockDevice('${device.id}')">🔓 Unlock</button>`
                }
            </td>
        </tr>
    `).join('');
}

// Update stats
function updateStats() {
    document.getElementById('totalDevices').textContent = devices.length;
    document.getElementById('activeDevices').textContent = 
        devices.filter(d => d.status === 'active').length;
    document.getElementById('lockedDevices').textContent = 
        devices.filter(d => d.status === 'locked').length;
}

// Lock device
async function lockDevice(deviceId) {
    try {
        const response = await fetch(`${API_URL}/commands/lock/${deviceId}.json`, {
            method: 'POST'
        });
        showNotification('Lock command sent');
        setTimeout(loadDevices, 2000);
    } catch (error) {
        showNotification('Error sending command', 'error');
    }
}

// Unlock device
async function unlockDevice(deviceId) {
    try {
        const response = await fetch(`${API_URL}/commands/unlock/${deviceId}.json`, {
            method: 'POST'
        });
        showNotification('Unlock command sent');
        setTimeout(loadDevices, 2000);
    } catch (error) {
        showNotification('Error sending command', 'error');
    }
}

// Generate QR code for Android enrollment
async function generateQR() {
    const qrData = {
        "android.app.extra.PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME": "com.google.android.apps.work.clouddpc/.receivers.CloudDeviceAdminReceiver",
        "android.app.extra.PROVISIONING_DEVICE_ADMIN_SIGNATURE_CHECKSUM": "I5Y9S4N4S3V0V3V3",
        "android.app.extra.PROVISIONING_DEVICE_ADMIN_PACKAGE_NAME": "com.google.android.apps.work.clouddpc",
        "android.app.extra.PROVISIONING_SUPPORT_URL": "https://support.google.com/work/android",
        "android.app.extra.PROVISIONING_DEVICE_ADMIN_DOWNLOAD_URL": "https://play.google.com/managed/downloadManagingApp?identifier=setup"
    };
    
    const qrContainer = document.getElementById('qrDisplay');
    qrContainer.innerHTML = '';
    
    QRCode.toCanvas(JSON.stringify(qrData), { width: 250 }, (err, canvas) => {
        if (err) {
            qrContainer.innerHTML = 'Error generating QR';
        } else {
            qrContainer.appendChild(canvas);
        }
    });
}

// Add device manually
async function addDevice() {
    const name = document.getElementById('deviceName').value;
    if (!name) {
        showNotification('Please enter a device name', 'error');
        return;
    }
    
    const newDevice = {
        id: Date.now().toString(),
        name: name,
        status: 'active',
        lastSeen: new Date().toISOString()
    };
    
    // In a real app, you'd POST to your backend
    devices.push(newDevice);
    renderDevices();
    updateStats();
    closeAddDeviceModal();
    showNotification('Device added');
}

// UI Helpers
function showQRModal() {
    document.getElementById('qrModal').style.display = 'flex';
}

function closeQRModal() {
    document.getElementById('qrModal').style.display = 'none';
}

function showAddDeviceModal() {
    document.getElementById('addDeviceModal').style.display = 'flex';
}

function closeAddDeviceModal() {
    document.getElementById('addDeviceModal').style.display = 'none';
}

function showNotification(message, type = 'success') {
    const notification = document.getElementById('notification');
    notification.textContent = message;
    notification.style.background = type === 'success' ? '#4caf50' : '#f44336';
    notification.style.display = 'block';
    setTimeout(() => {
        notification.style.display = 'none';
    }, 3000);
}

// Auto-refresh every 30 seconds
setInterval(loadDevices, 30000);
