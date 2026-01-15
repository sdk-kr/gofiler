package main

import (
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

// 파일 업로드 핸들러
func uploadHandler(c *gin.Context) {
	// 파일 또는 URL 확인
	file, fileHeader, fileErr := c.Request.FormFile("file")
	url := c.PostForm("url")

	// 파일과 URL 둘 다 제공되지 않은 경우
	if fileErr != nil && url == "" {
		respondWithProblem(c, http.StatusBadRequest, "파일 또는 URL을 제공해야 합니다.")
		return
	}

	// 파일과 URL 둘 다 제공된 경우
	if fileErr == nil && url != "" {
		respondWithProblem(c, http.StatusBadRequest, "파일과 URL 중 하나만 제공해야 합니다.")
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
	} else {
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
