# 🛡️ PQC API Service (Post-Quantum Cryptography)

> **양자 컴퓨터 위협에 대응하는 NIST 표준 암호(ML-KEM, ML-DSA) API 서버**

이 프로젝트는 **Spring Boot 4.x**와 **Bouncy Castle(LTS)**을 기반으로 구축된 양자 내성 암호 API 서비스입니다.  
상태를 저장하지 않는 **Stateless 아키텍처**이며, **Rate Limiting**과 **Input Validation**이 적용되어 있어 즉시 배포 가능한 수준의 보안성을 갖추고 있습니다.

---

## 🛠 기술 스택 (Tech Stack)

- **Core:** Spring Boot 4.0.1 (Java 17+)
- **Crypto Engine:** Bouncy Castle Provider v2.73.10 (LTS)
- **Security:**
    - **Bucket4j:** DoS 방지 (Rate Limiting)
    - **Validation:** Strict Base64 검증 및 Input Sanitization
- **Standard:** NIST ML-KEM (Key Exchange), NIST ML-DSA (Digital Signature)

---

## 🚀 실행 방법 (Getting Started)

### 1. 서버 구동
터미널에서 아래 명령어를 실행하세요.
```bash
# Mac / Linux
./gradlew bootRun

# Windows (PowerShell)
./gradlew.bat bootRun

```

* 서버가 시작되면 `http://localhost:8080` 포트가 열립니다.

### 2. 주의 사항 (Security Policy)

* **Rate Limit:** IP당 **초당 20회** 요청 제한 (초과 시 `429 Too Many Requests`)
* **Key Format:** 모든 키 값은 **Base64** 문자열이어야 합니다. (공백/개행은 서버가 자동 제거)

---

## 🧪 테스트 가이드 (API Usage & Test)

Postman이나 터미널(cURL)을 사용하여 아래 시나리오를 순서대로 진행해 보세요.

### 1️⃣ 시나리오 1: 비밀키 교환 (ML-KEM)

> **상황:** 앨리스(Server)와 밥(Client)이 서로 양자 내성 암호화된 비밀키를 공유하고 싶습니다.

#### Step 1. 키 쌍 생성 (Alice)

가장 먼저 알고리즘에 맞는 키 쌍을 생성합니다.

**Request (Terminal):**

```bash
curl -X POST http://localhost:8080/api/v1/pqc/keys \
   -H "Content-Type: application/json" \
   -d '{"type": "ML_KEM_768"}'

```

👉 **결과:** 응답으로 온 `publicKey`를 복사해 두세요.

#### Step 2. 키 캡슐화 (Bob)

밥은 앨리스의 공개키를 이용해 비밀키를 만들고 암호화합니다.

**Request:**

```bash
curl -X POST http://localhost:8080/api/v1/pqc/kem/encapsulate \
   -H "Content-Type: application/json" \
   -d '{
         "publicKey": "STEP1에서_받은_publicKey_붙여넣기"
       }'

```

👉 **결과:**

1. `sharedSecret`: 밥이 가질 비밀키 (A)
2. `ciphertext`: 앨리스에게 보낼 암호문 (복사하세요)

#### Step 3. 키 디캡슐화 (Alice)

앨리스는 자신의 개인키로 암호문을 풀어 비밀키를 얻습니다.

**Request:**

```bash
curl -X POST http://localhost:8080/api/v1/pqc/kem/decapsulate \
   -H "Content-Type: application/json" \
   -d '{
         "privateKey": "STEP1에서_받은_privateKey_붙여넣기",
         "ciphertext": "STEP2에서_받은_ciphertext_붙여넣기"
       }'

```

👉 **검증:** 여기서 나온 `sharedSecret`이 **Step 2의 (A)와 똑같은지 확인**하세요. 같다면 성공!

---

### 2️⃣ 시나리오 2: 전자 서명 (ML-DSA)

> **상황:** 중요한 문서("연봉 계약서")가 위변조되지 않았음을 증명합니다.

#### Step 1. 서명용 키 생성

**Request:**

```bash
curl -X POST http://localhost:8080/api/v1/pqc/keys \
   -H "Content-Type: application/json" \
   -d '{"type": "ML_DSA_65"}'

```

👉 **결과:** `publicKey`, `privateKey` 확보.

#### Step 2. 서명 생성 (Sign)

내 개인키로 문서에 도장을 찍습니다.

**Request:**

```bash
curl -X POST http://localhost:8080/api/v1/pqc/dsa/sign \
   -H "Content-Type: application/json" \
   -d '{
         "privateKeyBase64": "STEP1_privateKey_붙여넣기",
         "message": "Approved by RootLab"
       }'

```

👉 **결과:** `signature` (매우 긴 문자열) 복사.

#### Step 3. 서명 검증 (Verify)

공개키를 가진 누구나 이 서명이 진짜인지 확인합니다.

**Request:**

```bash
curl -X POST http://localhost:8080/api/v1/pqc/dsa/verify \
   -H "Content-Type: application/json" \
   -d '{
         "publicKey": "STEP1_publicKey_붙여넣기",
         "message": "Approved by RootLab",
         "signature": "STEP2_signature_붙여넣기"
       }'

```

👉 **검증:** 응답이 `{"valid": true}` 면 성공!
*(팁: message 내용을 "Rejected"로 바꿔서 보내보세요. false가 나와야 합니다.)*

---

## 🛑 에러 코드 가이드 (Troubleshooting)

| Status | Error Code | 원인 및 해결 |
| --- | --- | --- |
| **400** | `Malformed JSON Request` | Body 포맷이 깨졌거나 비어있습니다. JSON 문법을 확인하세요. |
| **400** | `Validation Error` | 필수 값이 누락되었거나, 키 값이 Base64 형식이 아닙니다. |
| **429** | `Too Many Requests` | 요청이 너무 많습니다 (초당 20회 제한). 잠시 후 시도하세요. |
| **500** | `Cryptography Error` | 키 쌍이 맞지 않거나, 서명 형식이 잘못되었습니다. |

---

### 🔒 Security Note

* 이 서버는 **키를 절대 저장하지 않습니다.** (Stateless)
* 모든 연산은 **SecureRandom** 난수 생성기를 사용합니다.
* 예외 발생 시 내부 스택트레이스(Stacktrace)는 노출되지 않습니다.