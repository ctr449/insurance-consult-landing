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
