// license-server/server.js
// Railway 배포용 라이센스 검증 서버
// 환경변수: PADDLE_API_KEY, PADDLE_WEBHOOK_SECRET

const express = require('express');
const crypto = require('crypto');
const app = express();

// Webhook은 raw body 필요
app.use('/webhook/paddle', express.raw({ type: 'application/json' }));
app.use(express.json());

// CORS - Figma 플러그인에서 호출 허용
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

const PADDLE_API = 'https://api.paddle.com';
const PADDLE_API_KEY = process.env.PADDLE_API_KEY;
const PADDLE_WEBHOOK_SECRET = process.env.PADDLE_WEBHOOK_SECRET;

// 인메모리 라이센스 저장소 (Railway 재시작 시 초기화됨 - 추후 DB 연동 권장)
// key: licenseKey(=subscriptionId), value: { figmaUserId, instanceId, active }
const licenses = {};

// ── 헬스 체크 ──────────────────────────────
app.get('/health', (req, res) => {
  res.json({ ok: true, ts: Date.now() });
});

// ── Paddle Webhook 수신 ────────────────────
// 결제 완료 시 라이센스 자동 등록
app.post('/webhook/paddle', (req, res) => {
  try {
    // 서명 검증
    if (PADDLE_WEBHOOK_SECRET) {
      const sig = req.headers['paddle-signature'];
      const ts = sig?.match(/ts=(\d+)/)?.[1];
      const h1 = sig?.match(/h1=([a-f0-9]+)/)?.[1];
      if (!ts || !h1) return res.status(401).json({ error: '서명 없음' });

      const signed = `${ts}:${req.body.toString()}`;
      const expected = crypto
        .createHmac('sha256', PADDLE_WEBHOOK_SECRET)
        .update(signed)
        .digest('hex');

      if (expected !== h1) return res.status(401).json({ error: '서명 불일치' });
    }

    const event = JSON.parse(req.body.toString());
    const type = event.event_type;

    // 결제 완료 또는 구독 활성화 시 라이센스 등록
    if (type === 'transaction.completed' || type === 'transaction.paid' || type === 'subscription.activated') {
      const subId = event.data?.subscription_id || event.data?.id;
      const email = event.data?.customer?.email || event.data?.billing_details?.email || '';

      if (subId) {
        licenses[subId] = {
          active: true,
          email,
          figmaUserId: null,  // activate 시 등록
          instanceId: null,
          createdAt: new Date().toISOString()
        };
        console.log(`✅ 라이센스 등록: ${subId} (${email})`);
      }
    }

    // 구독 취소 시 비활성화
    if (type === 'subscription.canceled') {
      const subId = event.data?.id;
      if (subId && licenses[subId]) {
        licenses[subId].active = false;
        console.log(`❌ 라이센스 비활성화: ${subId}`);
      }
    }

    res.json({ ok: true });
  } catch (e) {
    console.error('webhook error:', e);
    res.status(500).json({ error: '서버 오류' });
  }
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
    // Paddle API로 구독 상태 확인
    const response = await fetch(`${PADDLE_API}/subscriptions/${licenseKey}`, {
      headers: {
        'Authorization': `Bearer ${PADDLE_API_KEY}`,
        'Content-Type': 'application/json'
      }
    });

    if (!response.ok) {
      return res.json({ activated: false, error: '유효하지 않은 라이센스 키입니다.' });
    }

    const data = await response.json();
    const status = data.data?.status;

    if (status !== 'active' && status !== 'trialing') {
      return res.json({ activated: false, error: `라이센스가 활성 상태가 아닙니다. (${status})` });
    }

    // 라이센스 등록/업데이트
    licenses[licenseKey] = {
      ...(licenses[licenseKey] || {}),
      active: true,
      figmaUserId,
      figmaUserName: figmaUserName || 'Unknown',
      instanceId,
      activatedAt: new Date().toISOString()
    };

    console.log(`✅ 활성화: ${licenseKey} → ${figmaUserId}`);
    return res.json({ activated: true, instanceId });

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
    // 인메모리 캐시 먼저 확인
    const cached = licenses[licenseKey];
    if (cached && cached.active && cached.figmaUserId) {
      // Paddle API로 최신 상태 재확인
      const response = await fetch(`${PADDLE_API}/subscriptions/${licenseKey}`, {
        headers: {
          'Authorization': `Bearer ${PADDLE_API_KEY}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        const status = data.data?.status;
        const valid = status === 'active' || status === 'trialing';
        licenses[licenseKey].active = valid;
        return res.json({ valid });
      }
      // API 실패 시 캐시 기준으로 응답
      return res.json({ valid: cached.active });
    }

    return res.json({ valid: false });

  } catch (e) {
    console.error('validate error:', e);
    // 네트워크 오류 시 캐시 기준 응답
    const cached = licenses[licenseKey];
    return res.json({ valid: !!(cached?.active) });
  }
});

// ── 라이센스 비활성화 ──────────────────────
// POST /deactivate
// body: { licenseKey, instanceId }
app.post('/deactivate', async (req, res) => {
  const { licenseKey, instanceId } = req.body;
  if (!licenseKey || !instanceId) {
    return res.status(400).json({ deactivated: false, error: '필수 파라미터 누락' });
  }

  if (licenses[licenseKey]) {
    licenses[licenseKey].active = false;
    licenses[licenseKey].figmaUserId = null;
    console.log(`🔓 비활성화: ${licenseKey}`);
  }

  return res.json({ deactivated: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✦ Design Capture License Server (Paddle) running on port ${PORT}`);
});
