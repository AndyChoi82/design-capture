// license-server/server.js
// Railway 배포용 라이센스 검증 서버
// 환경변수: PADDLE_API_KEY, PADDLE_WEBHOOK_SECRET, POLAR_WEBHOOK_SECRET, DATABASE_URL, ADMIN_SECRET

const express = require('express');
const crypto = require('crypto');
const { Pool } = require('pg');
const app = express();

// Webhook은 raw body 필요
app.use('/webhook/paddle', express.raw({ type: 'application/json' }));
app.use('/webhook/polar', express.raw({ type: 'application/json' }));
app.use(express.json());

// CORS - Figma 플러그인에서 호출 허용
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Admin-Secret');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

const PADDLE_API = 'https://api.paddle.com';
const PADDLE_API_KEY = process.env.PADDLE_API_KEY;
const PADDLE_WEBHOOK_SECRET = process.env.PADDLE_WEBHOOK_SECRET;
const POLAR_WEBHOOK_SECRET = process.env.POLAR_WEBHOOK_SECRET;
const ADMIN_SECRET = process.env.ADMIN_SECRET;

// ── PostgreSQL 연결 ────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS licenses (
      license_key     TEXT PRIMARY KEY,
      email           TEXT,
      figma_user_id   TEXT,
      figma_user_name TEXT,
      instance_id     TEXT,
      active          BOOLEAN DEFAULT true,
      source          TEXT DEFAULT 'paddle',
      expires_at      TIMESTAMPTZ,
      created_at      TIMESTAMPTZ DEFAULT NOW(),
      activated_at    TIMESTAMPTZ
    );
  `);
  console.log('✅ DB 초기화 완료');
}

// ── 헬스 체크 ──────────────────────────────
app.get('/health', (req, res) => {
  res.json({ ok: true, ts: Date.now() });
});

// ── Admin 미들웨어 ─────────────────────────
function requireAdmin(req, res, next) {
  const secret = req.headers['x-admin-secret'];
  if (!ADMIN_SECRET || secret !== ADMIN_SECRET) {
    return res.status(401).json({ error: '인증 실패' });
  }
  next();
}

// ── 수동 라이선스 등록 ─────────────────────
app.post('/admin/grant', requireAdmin, async (req, res) => {
  const { licenseKey, email, figmaUserId, figmaUserName, expiresAt } = req.body;
  if (!licenseKey) {
    return res.status(400).json({ ok: false, error: 'licenseKey 필수' });
  }
  try {
    await pool.query(`
      INSERT INTO licenses (license_key, email, figma_user_id, figma_user_name, active, source, expires_at, activated_at)
      VALUES ($1, $2, $3, $4, true, 'manual', $5, NOW())
      ON CONFLICT (license_key) DO UPDATE SET
        email = EXCLUDED.email,
        figma_user_id = EXCLUDED.figma_user_id,
        figma_user_name = EXCLUDED.figma_user_name,
        active = true, source = 'manual',
        expires_at = EXCLUDED.expires_at, activated_at = NOW()
    `, [licenseKey, email || '', figmaUserId, figmaUserName || 'Team', expiresAt || null]);
    console.log(`🎁 수동 라이선스 등록: ${licenseKey} → ${figmaUserId}`);
    return res.json({ ok: true, licenseKey, figmaUserId, expiresAt: expiresAt || '무기한' });
  } catch (e) {
    return res.status(500).json({ ok: false, error: '서버 오류' });
  }
});

// ── 수동 라이선스 목록 ─────────────────────
app.get('/admin/licenses', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`SELECT * FROM licenses ORDER BY created_at DESC`);
    return res.json({ ok: true, licenses: result.rows });
  } catch (e) {
    return res.status(500).json({ ok: false, error: '서버 오류' });
  }
});

// ── 수동 라이선스 취소 ─────────────────────
app.post('/admin/revoke', requireAdmin, async (req, res) => {
  const { licenseKey } = req.body;
  if (!licenseKey) return res.status(400).json({ ok: false, error: 'licenseKey 필수' });
  try {
    await pool.query(`UPDATE licenses SET active = false WHERE license_key = $1`, [licenseKey]);
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ ok: false, error: '서버 오류' });
  }
});

// ── Polar Webhook ──────────────────────────
app.post('/webhook/polar', async (req, res) => {
  try {
    // 서명 검증
    if (POLAR_WEBHOOK_SECRET) {
      const webhookId = req.headers['webhook-id'];
      const webhookTimestamp = req.headers['webhook-timestamp'];
      const webhookSignature = req.headers['webhook-signature'];

      if (!webhookId || !webhookTimestamp || !webhookSignature) {
        return res.status(401).json({ error: '서명 헤더 없음' });
      }

      const signedContent = `${webhookId}.${webhookTimestamp}.${req.body.toString()}`;
      const secretBytes = Buffer.from(POLAR_WEBHOOK_SECRET.replace('whsec_', ''), 'base64');
      const hmac = crypto.createHmac('sha256', secretBytes);
      hmac.update(signedContent);
      const expectedSig = `v1,${hmac.digest('base64')}`;

      const signatures = webhookSignature.split(' ');
      const valid = signatures.some(sig => sig === expectedSig);
      if (!valid) return res.status(401).json({ error: '서명 불일치' });
    }

    const event = JSON.parse(req.body.toString());
    const type = event.type;
    console.log(`📨 Polar webhook: ${type}`);

    // 구독 활성화 시 라이선스 등록
    if (type === 'subscription.active' || type === 'order.paid') {
      const subId = event.data?.id;
      const email = event.data?.customer?.email || event.data?.billing_address?.email || '';

      if (subId) {
        await pool.query(`
          INSERT INTO licenses (license_key, email, active, source, created_at)
          VALUES ($1, $2, true, 'polar', NOW())
          ON CONFLICT (license_key) DO UPDATE SET active = true, email = EXCLUDED.email
        `, [subId, email]);
        console.log(`✅ Polar 라이선스 등록: ${subId} (${email})`);
      }
    }

    // 구독 취소/만료 시 비활성화
    if (type === 'subscription.canceled' || type === 'subscription.revoked') {
      const subId = event.data?.id;
      if (subId) {
        await pool.query(`UPDATE licenses SET active = false WHERE license_key = $1`, [subId]);
        console.log(`❌ Polar 라이선스 비활성화: ${subId}`);
      }
    }

    res.json({ ok: true });
  } catch (e) {
    console.error('polar webhook error:', e);
    res.status(500).json({ error: '서버 오류' });
  }
});

// ── Paddle Webhook ─────────────────────────
app.post('/webhook/paddle', async (req, res) => {
  try {
    if (PADDLE_WEBHOOK_SECRET) {
      const sig = req.headers['paddle-signature'];
      const ts = sig?.match(/ts=(\d+)/)?.[1];
      const h1 = sig?.match(/h1=([a-f0-9]+)/)?.[1];
      if (!ts || !h1) return res.status(401).json({ error: '서명 없음' });
      const signed = `${ts}:${req.body.toString()}`;
      const expected = crypto.createHmac('sha256', PADDLE_WEBHOOK_SECRET).update(signed).digest('hex');
      if (expected !== h1) return res.status(401).json({ error: '서명 불일치' });
    }
    const event = JSON.parse(req.body.toString());
    const type = event.event_type;
    if (type === 'transaction.completed' || type === 'subscription.activated') {
      const subId = event.data?.subscription_id || event.data?.id;
      const email = event.data?.customer?.email || '';
      if (subId) {
        await pool.query(`
          INSERT INTO licenses (license_key, email, active, source, created_at)
          VALUES ($1, $2, true, 'paddle', NOW())
          ON CONFLICT (license_key) DO UPDATE SET active = true, email = EXCLUDED.email
        `, [subId, email]);
      }
    }
    if (type === 'subscription.canceled') {
      const subId = event.data?.id;
      if (subId) await pool.query(`UPDATE licenses SET active = false WHERE license_key = $1`, [subId]);
    }
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: '서버 오류' });
  }
});

// ── 라이센스 활성화 ────────────────────────
app.post('/activate', async (req, res) => {
  const { licenseKey, instanceId, figmaUserId, figmaUserName } = req.body;
  if (!licenseKey || !figmaUserId) {
    return res.status(400).json({ activated: false, error: '필수 파라미터 누락' });
  }
  try {
    const result = await pool.query(`SELECT * FROM licenses WHERE license_key = $1`, [licenseKey]);
    const row = result.rows[0];

    if (row) {
      // 수동 또는 Polar 라이선스
      if (row.source === 'manual' || row.source === 'polar') {
        if (!row.active) return res.json({ activated: false, error: '비활성화된 라이선스입니다.' });
        if (row.expires_at && new Date(row.expires_at) < new Date()) {
          await pool.query(`UPDATE licenses SET active = false WHERE license_key = $1`, [licenseKey]);
          return res.json({ activated: false, error: '라이선스 유효기간이 만료되었습니다.' });
        }
        await pool.query(`
          UPDATE licenses SET figma_user_id=$1, figma_user_name=$2, instance_id=$3, activated_at=NOW()
          WHERE license_key=$4
        `, [figmaUserId, figmaUserName || 'Unknown', instanceId, licenseKey]);
        console.log(`✅ ${row.source} 라이선스 활성화: ${licenseKey} → ${figmaUserId}`);
        return res.json({ activated: true, instanceId });
      }
    }

    // Paddle 구독 확인
    const response = await fetch(`${PADDLE_API}/subscriptions/${licenseKey}`, {
      headers: { 'Authorization': `Bearer ${PADDLE_API_KEY}` }
    });
    if (!response.ok) return res.json({ activated: false, error: '유효하지 않은 라이센스 키입니다.' });
    const data = await response.json();
    const status = data.data?.status;
    if (status !== 'active' && status !== 'trialing') {
      return res.json({ activated: false, error: `라이센스가 활성 상태가 아닙니다. (${status})` });
    }
    await pool.query(`
      INSERT INTO licenses (license_key, figma_user_id, figma_user_name, instance_id, active, source, activated_at)
      VALUES ($1, $2, $3, $4, true, 'paddle', NOW())
      ON CONFLICT (license_key) DO UPDATE SET
        figma_user_id=EXCLUDED.figma_user_id, figma_user_name=EXCLUDED.figma_user_name,
        instance_id=EXCLUDED.instance_id, active=true, activated_at=NOW()
    `, [licenseKey, figmaUserId, figmaUserName || 'Unknown', instanceId]);
    return res.json({ activated: true, instanceId });
  } catch (e) {
    console.error('activate error:', e);
    return res.status(500).json({ activated: false, error: '서버 오류. 잠시 후 다시 시도해주세요.' });
  }
});

// ── 라이센스 검증 ──────────────────────────
app.post('/validate', async (req, res) => {
  const { licenseKey } = req.body;
  if (!licenseKey) return res.status(400).json({ valid: false });
  try {
    const result = await pool.query(`SELECT * FROM licenses WHERE license_key = $1`, [licenseKey]);
    const row = result.rows[0];
    if (!row || !row.active) return res.json({ valid: false });

    if (row.source === 'manual' || row.source === 'polar') {
      if (row.expires_at && new Date(row.expires_at) < new Date()) {
        await pool.query(`UPDATE licenses SET active = false WHERE license_key = $1`, [licenseKey]);
        return res.json({ valid: false });
      }
      return res.json({ valid: true });
    }

    // Paddle API 확인
    try {
      const response = await fetch(`${PADDLE_API}/subscriptions/${licenseKey}`, {
        headers: { 'Authorization': `Bearer ${PADDLE_API_KEY}` }
      });
      if (response.ok) {
        const data = await response.json();
        const status = data.data?.status;
        const valid = status === 'active' || status === 'trialing';
        await pool.query(`UPDATE licenses SET active = $1 WHERE license_key = $2`, [valid, licenseKey]);
        return res.json({ valid });
      }
    } catch (_) {}
    return res.json({ valid: row.active });
  } catch (e) {
    return res.status(500).json({ valid: false });
  }
});

// ── 라이센스 비활성화 ──────────────────────
app.post('/deactivate', async (req, res) => {
  const { licenseKey } = req.body;
  if (!licenseKey) return res.status(400).json({ deactivated: false });
  try {
    await pool.query(`UPDATE licenses SET active = false, figma_user_id = null WHERE license_key = $1`, [licenseKey]);
    return res.json({ deactivated: true });
  } catch (e) {
    return res.status(500).json({ deactivated: false });
  }
});

const PORT = process.env.PORT || 3000;
initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`✦ Design Capture License Server (Paddle + Polar + PostgreSQL) running on port ${PORT}`);
  });
}).catch(err => {
  console.error('DB 초기화 실패:', err);
  process.exit(1);
});
