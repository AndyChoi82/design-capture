// license-server/server.js
// Railway 배포용 라이센스 검증 서버
// 환경변수: LS_API_KEY (LemonSqueezy API Key)

const express = require('express');
const app = express();
app.use(express.json());

// CORS - Figma 플러그인에서 호출 허용
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

const LS_API = 'https://api.lemonsqueezy.com/v1/licenses';

// ── 헬스 체크 ──────────────────────────────
app.get('/health', (req, res) => {
  res.json({ ok: true, ts: Date.now() });
});

// ── 라이센스 활성화 ────────────────────────
// POST /activate
// body: { licenseKey, instanceId, figmaUserId, figmaUserName }
app.post('/activate', async (req, res) => {
  const { licenseKey, instanceId, figmaUserId, figmaUserName } = req.body;
  if (!licenseKey || !figmaUserId) {
    return res.status(400).json({ activated: false, error: '필수 파라미터 누락' });
  }
  try {
    const response = await fetch(`${LS_API}/activate`, {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        license_key: licenseKey,
        instance_name: figmaUserId   // Figma 계정당 1개 제한
      })
    });
    const data = await response.json();
    if (data.activated) {
      return res.json({ activated: true, instanceId: data.instance?.id });
    }
    // LemonSqueezy 에러 처리
    const errMsg = data.error || '유효하지 않은 라이센스 키입니다.';
    return res.json({ activated: false, error: errMsg });
  } catch (e) {
    console.error('activate error:', e);
    return res.status(500).json({ activated: false, error: '서버 오류. 잠시 후 다시 시도해주세요.' });
  }
});

// ── 라이센스 검증 ──────────────────────────
// POST /validate
// body: { licenseKey, instanceId }
app.post('/validate', async (req, res) => {
  const { licenseKey, instanceId } = req.body;
  if (!licenseKey) {
    return res.status(400).json({ valid: false, error: '라이센스 키 누락' });
  }
  try {
    const response = await fetch(`${LS_API}/validate`, {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        license_key: licenseKey,
        instance_id: instanceId
      })
    });
    const data = await response.json();
    return res.json({ valid: data.valid === true });
  } catch (e) {
    console.error('validate error:', e);
    return res.status(500).json({ valid: false, error: '서버 오류' });
  }
});

// ── 라이센스 비활성화 (기기 교체/포맷 시) ──
// POST /deactivate
// body: { licenseKey, instanceId }
app.post('/deactivate', async (req, res) => {
  const { licenseKey, instanceId } = req.body;
  if (!licenseKey || !instanceId) {
    return res.status(400).json({ deactivated: false, error: '필수 파라미터 누락' });
  }
  try {
    const response = await fetch(`${LS_API}/deactivate`, {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        license_key: licenseKey,
        instance_id: instanceId
      })
    });
    const data = await response.json();
    return res.json({ deactivated: data.deactivated === true });
  } catch (e) {
    console.error('deactivate error:', e);
    return res.status(500).json({ deactivated: false, error: '서버 오류' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✦ Design Capture License Server running on port ${PORT}`);
});
