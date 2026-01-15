# Go 파일 업로드/다운로드 서버

Gin 프레임워크를 사용한 파일 업로드 및 다운로드 서버입니다.

## 기능

- 파일 업로드 (직접 업로드 또는 URL에서 다운로드)
- **API 키 인증** (Bearer Token 방식)
- **Rate Limiting** (분당 요청 횟수 제한)
- **요청 로깅 및 모니터링**
- 파일 다운로드
- 중복되지 않는 랜덤 파일명으로 저장 (UUID 사용)
- 최대 파일 크기 제한 (100MB)
- 디렉토리 트래버셜 공격 방지

## 설치 및 실행

### 환경 변수 설정

먼저 `.env` 파일을 생성하여 API 키를 설정합니다:

```bash
# .env.example을 복사하여 .env 파일 생성
cp .env.example .env
```

`.env` 파일 내용:
```env
# API 키 설정 (필수) - 안전한 랜덤 문자열로 변경하세요
API_KEY=your_secret_api_key_here

# Rate Limiting 설정 (선택사항)
RATE_LIMIT_PER_MINUTE=100

# 서버 포트 (선택사항)
PORT=9999
```

**중요**: 프로덕션 환경에서는 반드시 강력한 API 키로 변경하세요!

### Docker로 실행 (권장)

```bash
# Docker 컨테이너 빌드 및 실행
docker-compose up -d

# 로그 확인
docker-compose logs -f

# 서버 중지
docker-compose down
```

서버는 http://0.0.0.0:9999 에서 실행됩니다.

### 로컬에서 직접 실행

#### 1. 의존성 설치

```bash
go mod tidy
```

#### 2. 서버 실행

```bash
go run main.go
```

#### 3. 빌드 (선택사항)

```bash
go build -o gofiler
./gofiler
```

서버는 http://0.0.0.0:9999 에서 실행됩니다.

## API 엔드포인트

### 1. 파일 업로드 (인증 필요)
- **URL**: `POST /upload`
- **설명**: 파일을 업로드하거나 URL에서 파일을 다운로드하여 저장
- **인증**: Bearer Token 필요
- **Rate Limit**: 분당 100회 (기본값, 설정 가능)

**파일 업로드 방식:**
```bash
curl -X POST "http://127.0.0.1:9999/upload" \
  -H "Authorization: Bearer your_secret_api_key_here" \
  -F "file=@example.jpg"
```

**URL 다운로드 방식:**
```bash
curl -X POST "http://127.0.0.1:9999/upload" \
  -H "Authorization: Bearer your_secret_api_key_here" \
  -d "url=https://example.com/image.jpg"
```

**응답 예시:**
```json
{
  "message": "파일이 성공적으로 업로드되었습니다.",
  "filename": "b83dd18a.jpg",
  "original_filename": "example.jpg",
  "size": 102400,
  "download_url": "/files/b83dd18a.jpg",
  "view_url": "/view/b83dd18a.jpg"
}
```

### 2. 파일 다운로드 (인증 불필요)
- **URL**: `GET /files/{filename}`
- **설명**: 업로드된 파일을 다운로드

```bash
curl -O "http://127.0.0.1:9999/files/b83dd18a.jpg"
```

### 3. 파일 보기/다운로드 (인증 불필요)
- **URL**: `GET /view/{filename}`
- **설명**: 업로드된 파일을 보기/다운로드 (이미지는 브라우저에서 직접 표시, 다른 파일은 다운로드)

```bash
# 브라우저에서 접근
http://127.0.0.1:9999/view/b83dd18a.jpg
```

**동작 방식:**
- 이미지 파일(image/*)의 경우: 브라우저에서 직접 표시 (inline)
- 다른 파일의 경우: 다운로드 (attachment)

### 4. 서버 상태 확인
- **URL**: `GET /`
- **설명**: 서버 상태 및 사용 가능한 엔드포인트 확인

```bash
curl "http://127.0.0.1:9999/"
```

## 파일 저장 위치

업로드된 파일은 프로젝트 하위의 `files/` 폴더에 저장됩니다.

## n8n에서 사용하기

n8n 워크플로우에서 이 API를 사용하는 방법:

### 1. HTTP Request 노드 설정

1. **노드 추가**: "HTTP Request" 노드를 추가합니다
2. **Method**: POST
3. **URL**: `http://your-server:9999/upload`
4. **Authentication**: Generic Credential Type
   - Credential Type: Header Auth
   - Name: `Authorization`
   - Value: `Bearer your_secret_api_key_here`

### 2. 파일 업로드 설정

**방법 1: 바이너리 파일 업로드**
- Body Content Type: `Form-Data`
- Body Parameters:
  - Name: `file`
  - Type: `File`
  - Input Data Field Name: 이전 노드의 바이너리 데이터 필드명

**방법 2: URL에서 다운로드**
- Body Content Type: `Form URL Encoded`
- Body Parameters:
  - Name: `url`
  - Value: `https://example.com/image.jpg`

### 3. 응답 처리

업로드 성공 시 다음과 같은 JSON 응답을 받습니다:
```json
{
  "message": "파일이 성공적으로 업로드되었습니다.",
  "filename": "b83dd18a.jpg",
  "download_url": "/files/b83dd18a.jpg",
  "view_url": "/view/b83dd18a.jpg"
}
```

다음 노드에서 `{{ $json.download_url }}` 또는 `{{ $json.view_url }}`로 파일 URL을 참조할 수 있습니다.

## 보안 기능

- **API 키 인증**: Bearer Token 방식으로 업로드 엔드포인트 보호
- **Rate Limiting**: 분당 요청 횟수 제한으로 남용 방지
- **요청 로깅**: 모든 API 요청 로그 기록 (IP, 타임스탬프, 상태 코드, 응답 시간)
- 파일 경로 검증으로 디렉토리 트래버셜 공격 방지
- 파일 크기 제한 (100MB)
- UUID를 사용한 고유 파일명 생성으로 파일명 충돌 방지

## 기술 스택

- **언어**: Go 1.21+
- **웹 프레임워크**: Gin
- **UUID 생성**: google/uuid
- **환경변수 관리**: joho/godotenv
- **Rate Limiting**: ulule/limiter

## 프로젝트 구조

```
gofiler/
├── main.go              # 메인 애플리케이션 코드
├── go.mod               # Go 모듈 파일
├── go.sum               # Go 의존성 체크섬
├── .env                 # 환경변수 설정 (git 제외)
├── .env.example         # 환경변수 예시 파일
├── .gitignore           # Git 제외 파일 목록
├── Dockerfile           # Docker 이미지 빌드 파일
├── docker-compose.yml   # Docker Compose 설정
├── .dockerignore        # Docker 빌드 제외 파일 목록
├── README.md            # 프로젝트 문서
└── files/               # 업로드된 파일 저장 디렉토리 (자동 생성)
```

## Docker 설정

### Dockerfile
- 멀티 스테이지 빌드로 최적화된 이미지 생성
- Alpine Linux 기반으로 경량화
- 포트 9999 노출

### docker-compose.yml
- 포트 매핑: 9999:9999
- 볼륨 마운트: `./files:/root/files` (파일 영구 저장)
- 자동 재시작: `unless-stopped`
- 타임존: `Asia/Seoul`

## Python FastAPI 버전과의 차이점

이 Go 버전은 `file-server/` 디렉토리의 Python FastAPI 버전과 동일한 기능을 제공합니다:

1. **동일한 API 엔드포인트**: `/upload`, `/files/{filename}`, `/view/{filename}`
2. **동일한 기능**: 파일 업로드, URL에서 다운로드, 파일명 중복 방지
3. **동일한 보안 기능**: 파일 크기 제한, 경로 검증

**주요 차이점:**
- Python의 비동기 처리 대신 Go의 고루틴 사용
- FastAPI 대신 Gin 프레임워크 사용
- 의존성 관리: `requirements.txt` 대신 `go.mod` 사용