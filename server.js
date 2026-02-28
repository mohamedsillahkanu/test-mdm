const express = require('express');
const cors = require('cors');
const app = express();

app.use(cors({
  origin: ['https://mohamedsillahkanu.github.io', 'http://localhost:3000']
}));
app.use(express.json());

let devices = [];

app.get('/api/health', (req, res) => {
  res.json({ status: 'healthy' });
});

app.post('/api/generate-qr', (req, res) => {
  const qrData = {
    "android.app.extra.PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME": "com.google.android.apps.work.clouddpc/.receivers.CloudDeviceAdminReceiver",
    "android.app.extra.PROVISIONING_DEVICE_ADMIN_SIGNATURE_CHECKSUM": "I5Y9S4N4S3V0V3V3",
    "android.app.extra.PROVISIONING_DEVICE_ADMIN_PACKAGE_NAME": "com.google.android.apps.work.clouddpc",
    "android.app.extra.PROVISIONING_SUPPORT_URL": "https://support.google.com/work/android"
  };
  res.json({ qrData: JSON.stringify(qrData) });
});

app.get('/api/devices', (req, res) => {
  res.json(devices);
});

app.post('/api/lock-device/:deviceId', (req, res) => {
  const { deviceId } = req.params;
  const device = devices.find(d => d.id === deviceId);
  if (device) device.status = 'locked';
  res.json({ success: true, message: 'Device locked' });
});

app.post('/api/unlock-device/:deviceId', (req, res) => {
  const { deviceId } = req.params;
  const device = devices.find(d => d.id === deviceId);
  if (device) device.status = 'active';
  res.json({ success: true, message: 'Device unlocked' });
});

app.post('/api/enroll-device', (req, res) => {
  const { deviceName } = req.body;
  const newDevice = {
    id: Date.now().toString(),
    name: deviceName || 'New Device',
    status: 'active',
    lastSeen: new Date().toISOString()
  };
  devices.push(newDevice);
  res.json({ success: true, device: newDevice });
});

app.listen(3000, '0.0.0.0', () => {
  console.log('✅ Server running');
})
