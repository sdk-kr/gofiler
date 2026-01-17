package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/ulule/limiter/v3"
	mgin "github.com/ulule/limiter/v3/drivers/middleware/gin"
	"github.com/ulule/limiter/v3/drivers/store/memory"
)

const (
	// 파일 저장 디렉토리
	FilesDir = "files"
	// 최대 파일 크기 (100MB)
	MaxFileSize = 100 * 1024 * 1024
)

// 파일 업로드 응답 구조체
type UploadResponse struct {
	Message          string `json:"message"`
	Filename         string `json:"filename"`
	OriginalFilename string `json:"original_filename"`
	Size             int64  `json:"size"`
	DownloadURL      string `json:"download_url"`
	ViewURL          string `json:"view_url"`
}

// RFC 9457 Problem Details 응답 구조체
type ProblemDetail struct {
	Type      string `json:"type"`                // URI reference identifying the problem type
	Title     string `json:"title"`               // Short, human-readable summary
	Status    int    `json:"status"`              // HTTP status code
	Detail    string `json:"detail"`              // Human-readable explanation
	Instance  string `json:"instance"`            // URI reference for this specific occurrence
	Timestamp string `json:"timestamp,omitempty"` // ISO 8601 timestamp
}

// 에러 응답 구조체 (하위 호환성)
type ErrorResponse struct {
	Detail string `json:"detail"`
}

// 루트 응답 구조체
type RootResponse struct {
	Message   string            `json:"message"`
	Endpoints map[string]string `json:"endpoints"`
}

// 파일 형식 정보 구조체
type FileTypeInfo struct {
	Extension string
	MimeType  string
}

// 매직 넘버 (파일 시그니처) 정의
var magicNumbers = map[string]FileTypeInfo{
	// 이미지 형식
	"\x89PNG\r\n\x1a\n":    {".png", "image/png"},
	"\xff\xd8\xff":         {".jpg", "image/jpeg"},
	"GIF87a":               {".gif", "image/gif"},
	"GIF89a":               {".gif", "image/gif"},
	"RIFF":                 {".webp", "image/webp"}, // RIFF....WEBP (부분 매칭)
	// 오디오 형식
	"\xff\xfb":             {".mp3", "audio/mpeg"}, // MP3 프레임 헤더
	"\xff\xfa":             {".mp3", "audio/mpeg"},
	"\xff\xf3":             {".mp3", "audio/mpeg"},
	"\xff\xf2":             {".mp3", "audio/mpeg"},
	"ID3":                  {".mp3", "audio/mpeg"}, // MP3 with ID3 tag
	"OggS":                 {".ogg", "audio/ogg"},
	// 비디오 형식
	"\x00\x00\x00\x18ftypmp4": {".mp4", "video/mp4"},
	"\x00\x00\x00\x1cftypmp4": {".mp4", "video/mp4"},
	"\x00\x00\x00\x20ftypmp4": {".mp4", "video/mp4"},
	"ftyp":                    {".mp4", "video/mp4"}, // 일반적인 MP4 매칭
	// 문서 형식
	"%PDF":                 {".pdf", "application/pdf"},
	"PK\x03\x04":           {".zip", "application/zip"},
}

// MIME 타입에서 확장자 매핑
var mimeToExtension = map[string]string{
	"image/png":       ".png",
	"image/jpeg":      ".jpg",
	"image/gif":       ".gif",
	"image/webp":      ".webp",
	"audio/mpeg":      ".mp3",
	"audio/wav":       ".wav",
	"audio/ogg":       ".ogg",
	"video/mp4":       ".mp4",
	"application/pdf": ".pdf",
	"application/zip": ".zip",
}

// RFC 9457 Problem Detail 생성 헬퍼 함수
func newProblemDetail(status int, detail, instance string) ProblemDetail {
	// HTTP 상태 코드에 따른 표준 title 매핑
	titleMap := map[int]string{
		400: "Bad Request",
		401: "Unauthorized",
		403: "Forbidden",
		404: "Not Found",
		413: "Payload Too Large",
		500: "Internal Server Error",
	}

	title, ok := titleMap[status]
	if !ok {
		title = "Error"
	}

	return ProblemDetail{
		Type:      "about:blank", // 기본값, 필요시 커스텀 URI 사용 가능
		Title:     title,
		Status:    status,
		Detail:    detail,
		Instance:  instance,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
}

// RFC 9457 Problem Detail JSON 응답 헬퍼 함수
func respondWithProblem(c *gin.Context, status int, detail string) {
	c.Header("Content-Type", "application/problem+json")
	c.JSON(status, newProblemDetail(status, detail, c.Request.URL.Path))
	c.Abort()
}

// 고유한 파일명 생성 함수
func generateUniqueFilename(originalFilename string) string {
	ext := filepath.Ext(originalFilename)
	// UUID 앞 8자리만 사용 (충돌 확률: 1/4,294,967,296)
	uniqueName := uuid.New().String()[:8] + ext
	return uniqueName
}

// 파일 경로 검증 함수 (디렉토리 트래버셜 공격 방지)
func isSecurePath(basePath, filename string) bool {
	// 절대 경로로 변환
	absBasePath, err := filepath.Abs(basePath)
	if err != nil {
		return false
	}

	fullPath := filepath.Join(absBasePath, filename)
	absFullPath, err := filepath.Abs(fullPath)
	if err != nil {
		return false
	}

	// 파일 경로가 기본 디렉토리 하위에 있는지 확인
	return strings.HasPrefix(absFullPath, absBasePath+string(os.PathSeparator))
}

// URL에서 파일 다운로드 함수
func downloadFileFromURL(url string) ([]byte, string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, "", fmt.Errorf("URL 다운로드 실패: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("HTTP 에러: %d", resp.StatusCode)
	}

	// 파일 내용 읽기
	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("파일 읽기 실패: %v", err)
	}

	// 파일명 추정
	filename := "downloaded_file"

	// Content-Disposition 헤더에서 파일명 추출 시도
	contentDisposition := resp.Header.Get("Content-Disposition")
	if contentDisposition != "" && strings.Contains(contentDisposition, "filename=") {
		parts := strings.Split(contentDisposition, "filename=")
		if len(parts) > 1 {
			filename = strings.Trim(parts[1], "\"")
		}
	} else {
		// URL 경로에서 파일명 추출
		urlPath := strings.Split(url, "?")[0] // 쿼리 파라미터 제거
		baseName := path.Base(urlPath)
		if baseName != "" && baseName != "/" {
			filename = baseName
		} else {
			// Content-Type에서 확장자 추정
			contentType := resp.Header.Get("Content-Type")
			if contentType != "" {
				exts, _ := mime.ExtensionsByType(contentType)
				if len(exts) > 0 {
					filename = "downloaded_file" + exts[0]
				}
			}
		}
	}

	return content, filename, nil
}

// Base64 데이터 디코딩 함수
func decodeBase64File(base64Data string) ([]byte, string, error) {
	var data string
	var mimeType string

	// Data URL 형식 확인 (data:image/png;base64,...)
	if strings.HasPrefix(base64Data, "data:") {
		// data:image/png;base64,iVBORw0... 형식 파싱
		parts := strings.SplitN(base64Data, ",", 2)
		if len(parts) != 2 {
			return nil, "", fmt.Errorf("잘못된 Data URL 형식입니다")
		}

		// MIME 타입 추출
		mimeType = extractMimeTypeFromDataURL(parts[0])
		data = parts[1]
	} else {
		// 순수 base64 데이터
		data = base64Data
	}

	// Base64 디코딩
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		// URL-safe base64 시도
		decoded, err = base64.URLEncoding.DecodeString(data)
		if err != nil {
			// padding 없는 경우 시도
			decoded, err = base64.RawStdEncoding.DecodeString(data)
			if err != nil {
				return nil, "", fmt.Errorf("Base64 디코딩 실패: %v", err)
			}
		}
	}

	return decoded, mimeType, nil
}

// 바이트 데이터에서 파일 형식 감지 함수
func detectFileTypeFromBytes(data []byte) (string, string) {
	// 매직 넘버로 파일 형식 감지
	for magic, info := range magicNumbers {
		if len(data) >= len(magic) && bytes.HasPrefix(data, []byte(magic)) {
			// WebP 특수 처리: RIFF로 시작하고 WEBP 포함 확인
			if magic == "RIFF" && len(data) >= 12 {
				if !bytes.Equal(data[8:12], []byte("WEBP")) {
					continue // RIFF이지만 WEBP가 아님
				}
			}
			return info.Extension, info.MimeType
		}
	}

	// MP4 특수 처리: ftyp가 4바이트 이후에 올 수 있음
	if len(data) >= 12 {
		if bytes.Contains(data[:12], []byte("ftyp")) {
			return ".mp4", "video/mp4"
		}
	}

	// WAV 파일 감지: RIFF....WAVE
	if len(data) >= 12 && bytes.HasPrefix(data, []byte("RIFF")) {
		if bytes.Equal(data[8:12], []byte("WAVE")) {
			return ".wav", "audio/wav"
		}
	}

	// 기본값
	return ".bin", "application/octet-stream"
}

// Data URL에서 MIME 타입 추출 함수
func extractMimeTypeFromDataURL(dataURL string) string {
	// data:image/png;base64 형식에서 image/png 추출
	// "data:" 제거
	withoutPrefix := strings.TrimPrefix(dataURL, "data:")

	// ";base64" 또는 ";" 이전 부분 추출
	if idx := strings.Index(withoutPrefix, ";"); idx != -1 {
		return withoutPrefix[:idx]
	}

	return withoutPrefix
}

// 파일 업로드 핸들러
func uploadHandler(c *gin.Context) {
	// 파일, URL, Base64 데이터 확인
	file, fileHeader, fileErr := c.Request.FormFile("file")
	url := c.PostForm("url")
	base64Data := c.PostForm("base64_data")
	originalFilenameParam := c.PostForm("original_filename")

	// 옵션 개수 확인
	optionCount := 0
	if fileErr == nil {
		optionCount++
	}
	if url != "" {
		optionCount++
	}
	if base64Data != "" {
		optionCount++
	}

	// 아무것도 제공되지 않은 경우
	if optionCount == 0 {
		respondWithProblem(c, http.StatusBadRequest, "파일, URL, 또는 base64_data 중 하나를 제공해야 합니다.")
		return
	}

	// 두 개 이상 제공된 경우
	if optionCount > 1 {
		respondWithProblem(c, http.StatusBadRequest, "파일, URL, base64_data 중 하나만 제공해야 합니다.")
		return
	}

	var fileContent []byte
	var originalFilename string
	var err error

	if fileErr == nil {
		// 직접 파일 업로드 처리
		defer file.Close()

		// 파일 크기 확인
		if fileHeader.Size > MaxFileSize {
			respondWithProblem(c, http.StatusRequestEntityTooLarge, "파일 크기가 너무 큽니다. (최대 100MB)")
			return
		}

		// 파일 내용 읽기
		fileContent, err = io.ReadAll(file)
		if err != nil {
			respondWithProblem(c, http.StatusInternalServerError, fmt.Sprintf("파일 읽기 실패: %v", err))
			return
		}

		originalFilename = fileHeader.Filename
	} else if url != "" {
		// URL에서 파일 다운로드 처리
		fileContent, originalFilename, err = downloadFileFromURL(url)
		if err != nil {
			respondWithProblem(c, http.StatusBadRequest, err.Error())
			return
		}

		// 파일 크기 확인
		if int64(len(fileContent)) > MaxFileSize {
			respondWithProblem(c, http.StatusRequestEntityTooLarge, "다운로드한 파일 크기가 너무 큽니다. (최대 100MB)")
			return
		}
	} else if base64Data != "" {
		// Base64 데이터 처리
		var mimeType string
		fileContent, mimeType, err = decodeBase64File(base64Data)
		if err != nil {
			respondWithProblem(c, http.StatusBadRequest, err.Error())
			return
		}

		// 파일 크기 확인
		if int64(len(fileContent)) > MaxFileSize {
			respondWithProblem(c, http.StatusRequestEntityTooLarge, "디코딩된 파일 크기가 너무 큽니다. (최대 100MB)")
			return
		}

		// 파일명 결정
		if originalFilenameParam != "" {
			originalFilename = originalFilenameParam
		} else {
			// 매직 넘버로 파일 형식 감지
			ext, detectedMime := detectFileTypeFromBytes(fileContent)

			// Data URL에서 MIME 타입이 있으면 그것을 우선 사용
			if mimeType != "" && mimeType != detectedMime {
				if mappedExt, ok := mimeToExtension[mimeType]; ok {
					ext = mappedExt
				}
			}

			originalFilename = "uploaded_file" + ext
		}
	}

	// 고유한 파일명 생성
	uniqueFilename := generateUniqueFilename(originalFilename)
	filePath := filepath.Join(FilesDir, uniqueFilename)

	// 파일 저장
	err = os.WriteFile(filePath, fileContent, 0644)
	if err != nil {
		respondWithProblem(c, http.StatusInternalServerError, fmt.Sprintf("파일 저장 실패: %v", err))
		return
	}

	// 업로드 결과 반환
	c.JSON(http.StatusOK, UploadResponse{
		Message:          "파일이 성공적으로 업로드되었습니다.",
		Filename:         uniqueFilename,
		OriginalFilename: originalFilename,
		Size:             int64(len(fileContent)),
		DownloadURL:      fmt.Sprintf("/files/%s", uniqueFilename),
		ViewURL:          fmt.Sprintf("/view/%s", uniqueFilename),
	})
}

// 파일 다운로드 핸들러 (/files/{filename})
func downloadFileHandler(c *gin.Context) {
	filename := c.Param("filename")

	// 파일 경로 검증
	if !isSecurePath(FilesDir, filename) {
		respondWithProblem(c, http.StatusForbidden, "접근 권한이 없습니다.")
		return
	}

	filePath := filepath.Join(FilesDir, filename)

	// 파일 존재 여부 확인
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		respondWithProblem(c, http.StatusNotFound, "파일을 찾을 수 없습니다.")
		return
	}

	// 파일 다운로드
	c.File(filePath)
}

// 파일 보기 핸들러 (/view/{filename})
func viewFileHandler(c *gin.Context) {
	filename := c.Param("filename")

	// 파일 경로 검증
	if !isSecurePath(FilesDir, filename) {
		respondWithProblem(c, http.StatusForbidden, "접근 권한이 없습니다.")
		return
	}

	filePath := filepath.Join(FilesDir, filename)

	// 파일 존재 여부 확인
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		respondWithProblem(c, http.StatusNotFound, "파일을 찾을 수 없습니다.")
		return
	}

	// MIME 타입 추정
	ext := filepath.Ext(filename)
	mimeType := mime.TypeByExtension(ext)

	// 이미지 파일인지 확인
	isImage := strings.HasPrefix(mimeType, "image/")

	if isImage {
		// 이미지를 브라우저에서 직접 표시 (inline)
		c.Header("Content-Disposition", "inline")
		c.File(filePath)
	} else {
		// 이미지가 아닌 파일은 다운로드 (attachment)
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
		c.File(filePath)
	}
}

// 루트 핸들러
func rootHandler(c *gin.Context) {
	c.JSON(http.StatusOK, RootResponse{
		Message: "Go 파일 업로드/다운로드 서버",
		Endpoints: map[string]string{
			"upload":   "POST /upload - 파일 업로드 또는 URL에서 다운로드 (API 키 필요)",
			"download": "GET /files/{filename} - 파일 다운로드",
			"view":     "GET /view/{filename} - 파일 보기/다운로드",
		},
	})
}

// API 키 인증 미들웨어
func apiKeyAuthMiddleware() gin.HandlerFunc {
	apiKey := os.Getenv("API_KEY")
	if apiKey == "" {
		log.Fatal("API_KEY 환경변수가 설정되지 않았습니다")
	}

	return func(c *gin.Context) {
		// Authorization 헤더에서 Bearer 토큰 추출
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			respondWithProblem(c, http.StatusUnauthorized, "Authorization 헤더가 필요합니다")
			return
		}

		// Bearer 토큰 파싱
		const bearerPrefix = "Bearer "
		if !strings.HasPrefix(authHeader, bearerPrefix) {
			respondWithProblem(c, http.StatusUnauthorized, "Authorization 헤더는 'Bearer {API_KEY}' 형식이어야 합니다")
			return
		}

		token := strings.TrimPrefix(authHeader, bearerPrefix)

		// API 키 검증
		if token != apiKey {
			respondWithProblem(c, http.StatusUnauthorized, "유효하지 않은 API 키입니다")
			return
		}

		c.Next()
	}
}

// 로깅 미들웨어
func loggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		startTime := time.Now()

		// 요청 처리
		c.Next()

		// 로그 출력
		duration := time.Since(startTime)
		statusCode := c.Writer.Status()
		clientIP := c.ClientIP()
		method := c.Request.Method
		path := c.Request.URL.Path

		log.Printf("[%s] %s %s | Status: %d | Duration: %v | IP: %s",
			time.Now().Format("2006-01-02 15:04:05"),
			method,
			path,
			statusCode,
			duration,
			clientIP,
		)
	}
}

func main() {
	// .env 파일 로드
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: .env 파일을 찾을 수 없습니다. 환경변수를 직접 설정해야 합니다.")
	}

	// files 디렉토리 생성
	if err := os.MkdirAll(FilesDir, os.ModePerm); err != nil {
		log.Fatalf("파일 디렉토리 생성 실패: %v\n", err)
	}

	// Rate Limiter 설정
	rateLimitPerMinute := 100 // 기본값
	if envRate := os.Getenv("RATE_LIMIT_PER_MINUTE"); envRate != "" {
		if parsed, err := strconv.Atoi(envRate); err == nil {
			rateLimitPerMinute = parsed
		}
	}

	rate := limiter.Rate{
		Period: 1 * time.Minute,
		Limit:  int64(rateLimitPerMinute),
	}
	store := memory.NewStore()
	rateLimiter := limiter.New(store, rate)

	// Gin 라우터 생성
	r := gin.Default()

	// 전역 미들웨어 적용
	r.Use(loggingMiddleware())

	// 라우트 설정
	r.GET("/", rootHandler)

	// /upload 엔드포인트에만 인증 + Rate Limiting 적용
	r.POST("/upload",
		apiKeyAuthMiddleware(),
		mgin.NewMiddleware(rateLimiter),
		uploadHandler,
	)

	r.GET("/files/:filename", downloadFileHandler)
	r.GET("/view/:filename", viewFileHandler)

	// 포트 설정
	port := os.Getenv("PORT")
	if port == "" {
		port = "9999"
	}

	// 서버 시작
	log.Printf("서버 시작: http://0.0.0.0:%s\n", port)
	log.Printf("Rate Limit: %d requests/minute\n", rateLimitPerMinute)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("서버 시작 실패: %v\n", err)
	}
}
