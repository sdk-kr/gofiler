# 빌드 스테이지
FROM golang:1.21-alpine AS builder

# 작업 디렉토리 설정
WORKDIR /app

# Go 모듈 파일 복사 및 의존성 다운로드
COPY go.mod go.sum ./
RUN go mod download

# 소스 코드 복사
COPY . .

# 바이너리 빌드
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o gofiler .

# 실행 스테이지
FROM alpine:latest

# CA 인증서 설치 (HTTPS 요청을 위해 필요)
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# 빌더 스테이지에서 빌드된 바이너리 복사
COPY --from=builder /app/gofiler .

# files 디렉토리 생성
RUN mkdir -p files

# 포트 노출
EXPOSE 9999

# 서버 실행
CMD ["./gofiler"]
