package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

// CertInfo는 개별 인증서의 상세 정보를 담는 구조체입니다.
type CertInfo struct {
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	DNSNames     []string  `json:"dns_names,omitempty"` // 사이트 인증서에만 포함
	IsCA         bool      `json:"is_ca"`
	SignatureAlgo string    `json:"signature_algorithm"`
}

// Response는 API 응답의 전체 구조입니다.
type Response struct {
	TargetURL        string     `json:"target_url"`
	Certificates     []CertInfo `json:"certificates"`
	ChainValidation  string     `json:"chain_validation_message"`
}

// 에러 응답을 생성하는 헬퍼 함수
func createErrorResponse(statusCode int, message string) (events.APIGatewayProxyResponse, error) {
	return events.APIGatewayProxyResponse{
		StatusCode: statusCode,
		Body:       fmt.Sprintf(`{"error": "%s"}`, message),
		Headers:    map[string]string{"Content-Type": "application/json"},
	}, nil
}

func handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	ip := request.QueryStringParameters["ip"]
	hostname := request.QueryStringParameters["url"]

	if ip == "" || hostname == "" {
		return createErrorResponse(400, "Query parameters 'ip' and 'url' are required.")
	}

	// URL에서 호스트명만 정확히 추출
	parsedURL, err := url.Parse(hostname)
	if err == nil && parsedURL.Host != "" {
		hostname = parsedURL.Host
	}


	// TCP 연결 주소 설정
	address := net.JoinHostPort(ip, "443")

	// TLS 다이얼러 설정. `InsecureSkipVerify: true`로 설정하여 직접 체인을 검증합니다.
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return createErrorResponse(500, fmt.Sprintf("Failed to connect via TLS: %s", err.Error()))
	}
	defer conn.Close()

	// 연결 상태에서 인증서 체인 가져오기
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return createErrorResponse(500, "Server did not provide any certificates.")
	}

	// 각 인증서 정보 파싱
	var certInfos []CertInfo
	for _, cert := range certs {
		info := CertInfo{
			Subject:      cert.Subject.String(),
			Issuer:       cert.Issuer.String(),
			NotBefore:    cert.NotBefore.UTC(),
			NotAfter:     cert.NotAfter.UTC(),
			IsCA:         cert.IsCA,
			SignatureAlgo: cert.SignatureAlgorithm.String(),
		}
		// 사이트 인증서(첫 번째)에만 SANs 정보 추가
		if len(certInfos) == 0 {
			info.DNSNames = cert.DNSNames
		}
		certInfos = append(certInfos, info)
	}

	// 인증서 체인 검증
	intermediates := x509.NewCertPool()
	for i, cert := range certs {
		if i > 0 { // 0번째는 리프(사이트) 인증서이므로 제외
			intermediates.AddCert(cert)
		}
	}

	validationOpts := x509.VerifyOptions{
		DNSName:       hostname,
		Intermediates: intermediates,
		// 시스템의 루트 CA 풀을 사용
		// Netlify(AWS Lambda) 환경에 내장된 루트 CA 목록을 사용하게 됩니다.
	}
	
	validationMessage := "Certificate chain is valid."
	if _, err := certs.Verify(validationOpts); err != nil {
		validationMessage = fmt.Sprintf("Certificate chain verification failed: %s", err.Error())
	}

	// 최종 응답 데이터 구성
	responsePayload := Response{
		TargetURL:       fmt.Sprintf("https://%s", hostname),
		Certificates:    certInfos,
		ChainValidation: validationMessage,
	}

	jsonBody, err := json.MarshalIndent(responsePayload, "", "  ")
	if err != nil {
		return createErrorResponse(500, "Failed to serialize response.")
	}

	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Body:       string(jsonBody),
		Headers:    map[string]string{"Content-Type": "application/json"},
	}, nil
}

func main() {
	lambda.Start(handler)
}
