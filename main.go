// main.go 파일

package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"
)

// main 함수는 Netlify의 웹 서버로서 애플리케이션을 실행합니다.
func main() {
	// HTTP 핸들러 함수를 설정합니다.
	http.HandleFunc("/", handleRequest)

	// 포트를 지정하여 서버를 실행합니다.
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // 기본 포트 설정
	}

	// 서버 시작
	fmt.Printf("Server is listening on port %s\n", port)
	err := http.ListenAndServe(":"+port, nil)
	if err != nil {
		fmt.Println("Failed to start server:", err)
	}
}

// handleRequest 함수는 HTTP 요청을 처리하고 해당 웹사이트의 SSL 인증서 만료일을 반환합니다.
func handleRequest(w http.ResponseWriter, r *http.Request) {
	// 쿼리 파라미터에서 URL과 debug 값을 가져옵니다.
	query := r.URL.Query()
	rawURL := query.Get("url")
	debug := query.Get("debug")

	// URL이 제공되지 않으면 오류 메시지를 반환합니다.
	if rawURL == "" {
		http.Error(w, "Missing 'url' query parameter", http.StatusBadRequest)
		if debug == "true" {
			fmt.Println("Debug: URL 파라미터가 없습니다.")
		}
		return
	}

	// URL에서 호스트와 포트를 추출합니다.
	parsedURL, err := url.Parse(rawURL)
	if err != nil || parsedURL.Scheme != "https" || parsedURL.Host == "" {
		http.Error(w, "Invalid 'url' format. Example: https://example.com:8443", http.StatusBadRequest)
		if debug == "true" {
			fmt.Printf("Debug: 잘못된 URL 형식 - %v\n", err)
		}
		return
	}

	// 기본 포트가 없는 경우 443을 추가합니다.
	host := parsedURL.Host
	if parsedURL.Port() == "" {
		host = parsedURL.Hostname() + ":443"
	}

	// 호스트로 TLS 연결을 시도합니다.
	conn, err := tls.Dial("tcp", host, nil)
	if err != nil {
		http.Error(w, "Failed to connect to the server", http.StatusInternalServerError)
		if debug == "true" {
			fmt.Printf("Debug: 서버 연결 오류 - %v\n", err)
		}
		return
	}
	defer conn.Close()

	// 인증서를 가져옵니다.
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		http.Error(w, "No certificates found", http.StatusInternalServerError)
		if debug == "true" {
			fmt.Println("Debug: 인증서를 찾을 수 없습니다.")
		}
		return
	}

	// 첫 번째 인증서의 만료일을 가져옵니다.
	expiry := certs[0].NotAfter
	response := fmt.Sprintf("SSL certificate for %s expires on %s\n", rawURL, expiry.Format(time.RFC3339))

	// 만료일을 응답으로 반환합니다.
	w.Write([]byte(response))
}
