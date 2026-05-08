# 보험 상담 연결 랜딩

Express 기반 랜딩 페이지와 운용자(설계사/운영)용 상담 신청 목록입니다.

## 실행

```bash
cp .env.example .env
# .env 에 OPERATOR_PASSWORD, PII_ENCRYPTION_KEY(64자 hex) 설정
npm install
npm start
```

- 랜딩: http://localhost:3000  
- 운용자 로그인: http://localhost:3000/operator/login  

운영 시 `NODE_ENV=production` 과 HTTPS(리버스 프록시)를 사용하세요.

## 환경 변수

`.env.example` 참고. `data/` 는 신청 내역 저장용이며 저장소에 포함하지 않습니다.

## 백업/복구 (PostgreSQL)

운영 환경에서는 정기 백업을 반드시 설정하세요.

```bash
# 수동 백업
npm run backup:db

# 복구 (예시)
npm run restore:db -- ./backups/consult-20260508-180000.dump
```

- `backup:db`는 `pg_dump`로 `BACKUP_DIR`에 덤프를 생성합니다.
- `BACKUP_RETENTION_DAYS`보다 오래된 덤프는 자동 삭제됩니다.
- 운영에서는 크론(예: 하루 1회)으로 `npm run backup:db`를 실행하세요.

## 배포 (Render 예시)

1. [Render](https://render.com) 에서 **New → Web Service** → GitHub 저장소 `ctr449/insurance-consult-landing` 연결  
2. **Build Command**: `npm install`  
3. **Start Command**: `npm start`  
4. **Environment** 에 다음 추가:

| 변수 | 설명 |
|------|------|
| `NODE_ENV` | `production` |
| `OPERATOR_PASSWORD` | 운용자 로그인 비밀번호 (강하게 설정) |
| `PII_ENCRYPTION_KEY` | 64자리 hex (로컬 `.env` 와 **다르게** 새로 생성 권장) |
| `RETENTION_DAYS` | (선택) 기본 `90` |

Render가 부여하는 `PORT` 는 자동 사용됩니다.

### 신청 데이터를 잃지 않으려면

무료 웹 서비스는 디스크가 **재시작 시 초기화**될 수 있습니다. 상담 신청을 오래 보관하려면:

- Render에서 **Persistent Disk** 를 붙이고 마운트 경로(예: `/var/data`)를 정한 뒤  
  환경 변수 **`DATA_DIR=/var/data`** 를 설정하세요.

또는 나중에 DB(Supabase 등)로 옮기는 것을 권장합니다.

### 다른 호스팅

- **Railway**, **Fly.io** 도 Node 앱 + 동일 환경 변수로 동작합니다. HTTPS는 플랫폼이 앞단에서 처리합니다.
