// license-server/server.js
// Railway 배포용 라이센스 검증 서버
// 환경변수: PADDLE_API_KEY, PADDLE_WEBHOOK_SECRET, DATABASE_URL, ADMIN_SECRET

const express = require('express');
const crypto = require('crypto');
const { Pool } = require('pg');
const app = express();

// Webhook은 raw body 필요
app.use('/webhook/paddle', express.raw({ type: 'application/json' }));
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
const ADMIN_SECRET = process.env.ADMIN_SECRET; // 수동 등록 API 보호용

// ── PostgreSQL 연결 ────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// DB 초기화 - 테이블 없으면 생성
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS licenses (
      license_key     TEXT PRIMARY KEY,
      email           TEXT,
      figma_user_id   TEXT,
      figma_user_name TEXT,
      instance_id     TEXT,
      active          BOOLEAN DEFAULT true,
      source          TEXT DEFAULT 'paddle',  -- 'paddle' | 'manual'
      expires_at      TIMESTAMPTZ,            -- NULL이면 무기한 (Paddle 구독 기준)
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

// ── 수동 라이선스 등록 (팀원용) ───────────
// POST /admin/grant
// headers: { X-Admin-Secret: ... }
// body: { licenseKey, email, figmaUserId, figmaUserName, expiresAt }
// expiresAt 예시: "2026-12-31" 또는 null (무기한)
app.post('/admin/grant', requireAdmin, async (req, res) => {
  const { licenseKey, email, figmaUserId, figmaUserName, expiresAt } = req.body;
  if (!licenseKey || !figmaUserId) {
    return res.status(400).json({ ok: false, error: 'licenseKey, figmaUserId 필수' });
  }

  try {
    await pool.query(`
      INSERT INTO licenses (license_key, email, figma_user_id, figma_user_name, active, source, expires_at, activated_at)
      VALUES ($1, $2, $3, $4, true, 'manual', $5, NOW())
      ON CONFLICT (license_key) DO UPDATE SET
        email = EXCLUDED.email,
        figma_user_id = EXCLUDED.figma_user_id,
        figma_user_name = EXCLUDED.figma_user_name,
        active = true,
        source = 'manual',
        expires_at = EXCLUDED.expires_at,
        activated_at = NOW()
    `, [licenseKey, email || '', figmaUserId, figmaUserName || 'Team', expiresAt || null]);

    console.log(`🎁 수동 라이선스 등록: ${licenseKey} → ${figmaUserId} (${email})`);
    return res.json({ ok: true, licenseKey, figmaUserId, expiresAt: expiresAt || '무기한' });
  } catch (e) {
    console.error('grant error:', e);
    return res.status(500).json({ ok: false, error: '서버 오류' });
  }
});

// ── 수동 라이선스 목록 조회 ────────────────
// GET /admin/licenses
app.get('/admin/licenses', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT license_key, email, figma_user_id, figma_user_name, active, source, expires_at, created_at, activated_at
      FROM licenses ORDER BY created_at DESC
    `);
    return res.json({ ok: true, licenses: result.rows });
  } catch (e) {
    console.error('list error:', e);
    return res.status(500).json({ ok: false, error: '서버 오류' });
  }
});

// ── 수동 라이선스 비활성화 ─────────────────
// POST /admin/revoke
// body: { licenseKey }
app.post('/admin/revoke', requireAdmin, async (req, res) => {
  const { licenseKey } = req.body;
  if (!licenseKey) return res.status(400).json({ ok: false, error: 'licenseKey 필수' });

  try {
    await pool.query(`UPDATE licenses SET active = false WHERE license_key = $1`, [licenseKey]);
    console.log(`🚫 수동 라이선스 취소: ${licenseKey}`);
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ ok: false, error: '서버 오류' });
  }
});

// ── Paddle Webhook 수신 ────────────────────
app.post('/webhook/paddle', async (req, res) => {
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

    if (type === 'transaction.completed' || type === 'transaction.paid' || type === 'subscription.activated') {
      const subId = event.data?.subscription_id || event.data?.id;
      const email = event.data?.customer?.email || event.data?.billing_details?.email || '';

      if (subId) {
        await pool.query(`
          INSERT INTO licenses (license_key, email, active, source, created_at)
          VALUES ($1, $2, true, 'paddle', NOW())
          ON CONFLICT (license_key) DO UPDATE SET active = true, email = EXCLUDED.email
        `, [subId, email]);
        console.log(`✅ 라이센스 등록: ${subId} (${email})`);
      }
    }

    if (type === 'subscription.canceled') {
      const subId = event.data?.id;
      if (subId) {
        await pool.query(`UPDATE licenses SET active = false WHERE license_key = $1`, [subId]);
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
app.post('/activate', async (req, res) => {
  const { licenseKey, instanceId, figmaUserId, figmaUserName } = req.body;
  if (!licenseKey || !figmaUserId) {
    return res.status(400).json({ activated: false, error: '필수 파라미터 누락' });
  }

  try {
    // DB에서 라이선스 조회
    const result = await pool.query(`SELECT * FROM licenses WHERE license_key = $1`, [licenseKey]);
    const row = result.rows[0];

    if (row) {
      // 수동 등록 라이선스 처리
      if (row.source === 'manual') {
        if (!row.active) return res.json({ activated: false, error: '비활성화된 라이선스입니다.' });

        // 유효기간 체크
        if (row.expires_at && new Date(row.expires_at) < new Date()) {
          await pool.query(`UPDATE licenses SET active = false WHERE license_key = $1`, [licenseKey]);
          return res.json({ activated: false, error: '라이선스 유효기간이 만료되었습니다.' });
        }

        await pool.query(`
          UPDATE licenses SET figma_user_id=$1, figma_user_name=$2, instance_id=$3, activated_at=NOW()
          WHERE license_key=$4
        `, [figmaUserId, figmaUserName || 'Unknown', instanceId, licenseKey]);

        console.log(`✅ 수동 라이선스 활성화: ${licenseKey} → ${figmaUserId}`);
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

    // DB 저장/업데이트
    await pool.query(`
      INSERT INTO licenses (license_key, figma_user_id, figma_user_name, instance_id, active, source, activated_at)
      VALUES ($1, $2, $3, $4, true, 'paddle', NOW())
      ON CONFLICT (license_key) DO UPDATE SET
        figma_user_id = EXCLUDED.figma_user_id,
        figma_user_name = EXCLUDED.figma_user_name,
        instance_id = EXCLUDED.instance_id,
        active = true,
        activated_at = NOW()
    `, [licenseKey, figmaUserId, figmaUserName || 'Unknown', instanceId]);

    console.log(`✅ Paddle 활성화: ${licenseKey} → ${figmaUserId}`);
    return res.json({ activated: true, instanceId });

  } catch (e) {
    console.error('activate error:', e);
    return res.status(500).json({ activated: false, error: '서버 오류. 잠시 후 다시 시도해주세요.' });
  }
});

// ── 라이센스 검증 ──────────────────────────
app.post('/validate', async (req, res) => {
  const { licenseKey } = req.body;
  if (!licenseKey) return res.status(400).json({ valid: false, error: '라이센스 키 누락' });

  try {
    const result = await pool.query(`SELECT * FROM licenses WHERE license_key = $1`, [licenseKey]);
    const row = result.rows[0];

    if (!row || !row.active) return res.json({ valid: false });

    // 수동 라이선스: 유효기간 체크
    if (row.source === 'manual') {
      if (row.expires_at && new Date(row.expires_at) < new Date()) {
        await pool.query(`UPDATE licenses SET active = false WHERE license_key = $1`, [licenseKey]);
        return res.json({ valid: false });
      }
      return res.json({ valid: true });
    }

    // Paddle 라이선스: API로 최신 상태 확인
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

    // Paddle API 실패 시 DB 기준으로 응답
    return res.json({ valid: row.active });

  } catch (e) {
    console.error('validate error:', e);
    return res.status(500).json({ valid: false });
  }
});

// ── 라이센스 비활성화 ──────────────────────
app.post('/deactivate', async (req, res) => {
  const { licenseKey } = req.body;
  if (!licenseKey) return res.status(400).json({ deactivated: false, error: '필수 파라미터 누락' });

  try {
    await pool.query(`UPDATE licenses SET active = false, figma_user_id = null WHERE license_key = $1`, [licenseKey]);
    console.log(`🔓 비활성화: ${licenseKey}`);
    return res.json({ deactivated: true });
  } catch (e) {
    return res.status(500).json({ deactivated: false, error: '서버 오류' });
  }
});

const PORT = process.env.PORT || 3000;
initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`✦ Design Capture License Server (Paddle + PostgreSQL) running on port ${PORT}`);
  });
}).catch(err => {
  console.error('DB 초기화 실패:', err);
  process.exit(1);
});
