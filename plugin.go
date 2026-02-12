package traefik_securbase_access_plugin

import (
	"context"
  "fmt"
	"net/http"
  "net/http/httputil"
	"net/url"
	"encoding/json"
	//_ "regexp"
	//_ "strconv"
	"strings"
	"log"
	"time"
	"io"
	"bytes"
	//"github.com/golang-jwt/jwt/v5"
)

const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

type Config struct {
	Debug bool `json:"debug,omitempty" yaml:"debug,omitempty"`
	Enabled bool `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	HeaderName string `json:"headerName,omitempty" yaml:"headerName,omitempty"`
	SignKey string `json:"signKey,omitempty" yaml:"signKey,omitempty"`
	EncKey string `json:"encKey,omitempty" yaml:"encKey,omitempty"`
	ApiAccessURL string `json:"apiAccessURL,omitempty" yaml:"apiAccessURL,omitempty"`
	MockApiAccess bool `json:"mockApiAccess,omitempty" yaml:"mockApiAccess,omitempty"`
	MockHeaderValueValid string `json:"mockHeaderValueValid,omitempty" yaml:"mockHeaderValueValid,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		Debug: false,
		Enabled: true,
		HeaderName: "Authorization",
		SignKey: "",
		EncKey: "",
		ApiAccessURL: "http://localhost:8080/v1/api/key",
		MockApiAccess: false,
		MockHeaderValueValid: "",
	}
}

type Plugin struct {
	next http.Handler
	client *http.Client
	name string
	config *Config
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {

	plugin := &Plugin{
		next: next,
		client: &http.Client{}, 
		name: name,
		config: config,
	}

	log.Printf("AccessPlugin: Creado [%s]. Debug=%b Enabled=%b HeaderName=%s ApiAccessURL=%s\n", name, config.Debug, config.Enabled, config.HeaderName, config.ApiAccessURL)
	return plugin, nil
}

func (p *Plugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if !p.config.Enabled {
		log.Printf("AccessPlugin: DISABLED. Access allow. From '%s' (%s) method '%s' to '%s'", req.Host, req.RemoteAddr, req.Method, req.RequestURI)
		p.next.ServeHTTP(rw, req)
		return
	}
 	if req.Method == "OPTIONS" {
		log.Printf("AccessPlugin: ENABLED. Method OPTIONS allow. From '%s' (%s) method '%s' to '%s'", req.Host, req.RemoteAddr, req.Method, req.RequestURI)
		p.next.ServeHTTP(rw, req)
		return
	}

	domain := req.Host
	headerValue := req.Header.Get(p.config.HeaderName)

	if headerValue == "" {
		log.Printf("AccessPlugin: JWT EMPTY. UNAUTHORIZED. From '%s' (%s) method '%s' to '%s'", req.Host, req.RemoteAddr, req.Method, req.RequestURI)
		http.Error(rw, "Unauthorized", http.StatusUnauthorized)
		return

	} else { 
		if p.config.Debug {
			log.Printf("AccessPlugin: JWT FOUND for '%s'", domain)
		}

		token := strings.TrimPrefix(headerValue, "Bearer ")

		if p.config.MockApiAccess {
			log.Printf("AccessPlugin: MOCK-API-ACCESS ENABLED: '%s'", p.config.MockHeaderValueValid)
			if token == p.config.MockHeaderValueValid {
				log.Printf("AccessPlugin MOCK-API-ACCESS: ACCESS ALLOW. From '%s' (%s) method '%s' to '['%s']%s'", req.Host, req.RemoteAddr, req.Method, domain, req.RequestURI)
				p.next.ServeHTTP(rw, req)
			} else {
				log.Printf("AccessPlugin MOCK-API-ACCESS: ACCESS FILTER: FORBIDDEN. From '%s' (%s) method '%s' to '%s'", req.Host, req.RemoteAddr, req.Method, req.RequestURI)
				http.Error(rw, "Forbidden", http.StatusForbidden)				
			}
			return
		}

		if p.config.Debug {
			log.Printf("AccessPlugin: Parse JWE: %s", token)
		}
		claims, err := parseJWT(token, p.config.SignKey, p.config.EncKey)
		if err != nil {
			log.Printf("AccessPlugin: JWT INVALID. UNAUTHORIZED. From '%s' (%s) method '%s' to '%s' [Error: %s]", req.Host, req.RemoteAddr, req.Method, req.RequestURI, err.Error())
			http.Error(rw, "Invalid Token", http.StatusUnauthorized)
			return
		} 
		expired, err := isTokenExpired(claims)
		if err != nil {			
			log.Printf("AccessPlugin: JWT EXPIRED. FORBIDDEN. From '%s' (%s) method '%s' to '%s' [Error: %s]", req.Host, req.RemoteAddr, req.Method, req.RequestURI, err.Error())
			http.Error(rw, "Token Expired", http.StatusForbidden)
			return
		}
		if expired {
			log.Printf("AccessPlugin: JWT EXPIRED. FORBIDDEN. From '%s' (%s) method '%s' to '%s'", req.Host, req.RemoteAddr, req.Method, req.RequestURI)
			http.Error(rw, "Token Expired", http.StatusForbidden)
			return
		}

		//Se procede a consultar a la API Java
		//apiQuery := url.Values{}
		// apiQuery.Add("domain", req.Host)
		//apiFullURL := fmt.Sprintf("%s?%s", p.ApiAccessURL, apiQuery.Encode())
		apiFullURL := p.ApiAccessURL
		if p.config.Debug {
			log.Printf("AccessPlugin: Validate access for '%s': %s", domain, apiFullURL)
		}

		apiData := map[string]string{
			"ip": req.RemoteAddr,
			"domain": req.Host,
			"uri": req.RequestURI,
			"method": req.Method,

			"sub": claims["sub"].(string),
			"iss": claims["iss"].(string),

			"orgId": claims["orgId"].(string),
			"canal": claims["canal"].(string), 
			"version": claims["version"].(string),
		}

		// Convertir la estructura a JSON
		jsonApiData, err := json.Marshal(apiData)
		if err != nil {
			log.Printf("AccessPlugin: JWT JSON MARSHAL ERROR. From '%s' (%s) method '%s' to '%s' [Error: %s]", req.Host, req.RemoteAddr, req.Method, req.RequestURI, err.Error())
			http.Error(rw, "Internal Error", http.StatusInternalServerError)
			return
		}
		if p.config.Debug {
			log.Printf("AccessPlugin: JSON for '%s': %s", domain, jsonApiData)
		}

		httpApiReq, err := http.NewRequest(http.MethodPost, apiFullURL, bytes.NewBuffer(jsonApiData))
		// httpApiReq, err := http.NewRequest(http.MethodGet, apiFullURL, nil)
		if err != nil {
			log.Printf("AccessPlugin: REQUEST ACCESS FILTER ERROR. From '%s' (%s) method '%s' to '%s' [Error: %s]", req.Host, req.RemoteAddr, req.Method, req.RequestURI, err.Error())
			http.Error(rw, "Internal Error", http.StatusInternalServerError)
			return
		}
		//httpApiReq.Header.Set("Authorization", headerValue)
		httpApiReq.Header.Set("accept", "application/json")
		httpApiReq.Header.Set("Content-Type", "application/json")
		
		httpApiResp, err := p.client.Do(httpApiReq)
		if err != nil {
			log.Printf("AccessPlugin: RESPONSE ACCESS FILTER ERROR. From '%s' (%s) method '%s' to '%s' [Error: %s]", req.Host, req.RemoteAddr, req.Method, req.RequestURI, err.Error())
			http.Error(rw, "Internal Error", http.StatusInternalServerError)
			return
		}
		defer httpApiResp.Body.Close()
		apiRespBody, err := io.ReadAll(httpApiResp.Body)
		if err != nil {
			log.Printf("AccessPlugin: READ RESPONSE ACCESS FILTER ERROR. From '%s' (%s) method '%s' to '%s' [Error: %s]", req.Host, req.RemoteAddr, req.Method, req.RequestURI, err.Error())
			http.Error(rw, "Internal Error", http.StatusInternalServerError)
			return
		}
		if httpApiResp.StatusCode != http.StatusOK {
			log.Printf("AccessPlugin: RESPONSE ACCESS FILTER STATUS NOK [%d]. From '%s' (%s) method '%s' to '%s' [Error: %s]", httpApiResp.StatusCode, req.Host, req.RemoteAddr, req.Method, req.RequestURI, err.Error())
			http.Error(rw, "Internal Error", http.StatusInternalServerError)
			return
		}

		var apiResult struct {
			Success bool `json:"success"`
			Destination string `json:"destination,omitempty"`
			PrivateKeyComponent string `json:"privateKeyComponent,omitempty"`
			PrivateKeyComponentSize string `json:"privateKeyComponentSize,omitempty"`
			PrivateKeyComponentPrevio string `json:"privateKeyComponentPrevio,omitempty"`
			PrivateKeyComponentPrevioSize string `json:"privateKeyComponentPrevioSize,omitempty"`
		}
		err = json.Unmarshal(apiRespBody, &apiResult)
		if err != nil {
			log.Printf("AccessPlugin: READ RESPONSE ACCESS FILTER JSON MARSHAL ERROR. From '%s' (%s) method '%s' to '%s' [Error: %s]", req.Host, req.RemoteAddr, req.Method, req.RequestURI, err.Error())
			http.Error(rw, "Internal Error", http.StatusInternalServerError)
			return
		}

		log.Printf("AccessPlugin: JSON for '%s' Success:%b Destination:'%s'", domain, apiResult.Success, apiResult.Destination)
		if !apiResult.Success {
			log.Printf("AccessPlugin: ACCESS FILTER: FORBIDDEN. From '%s' (%s) method '%s' to '%s'", req.Host, req.RemoteAddr, req.Method, req.RequestURI)
			http.Error(rw, "Forbidden", http.StatusForbidden)
			return
		}

		if apiResult.Destination != "" {
			if p.config.Debug {
				log.Printf("AccessPlugin: Access allow. Redirect from '%s' to '%s'", domain, apiResult.Destination)
			}
			//--
			proxyTgtReq, err := url.Parse(apiResult.Destination)
			if err != nil {
				log.Printf("AccessPlugin: ACCESS FILTER INVALID TARGET URL='%s'. From '%s' (%s) method '%s' to '%s' [Error: %s]", apiResult.Destination, req.Host, req.RemoteAddr, req.Method, req.RequestURI, err.Error())
				http.Error(rw, "Internal Error", http.StatusInternalServerError)
				return
			}

			proxyTimeBegin := time.Now().Format(time.RFC3339Nano) //RFC3339

			proxyReq := httputil.NewSingleHostReverseProxy(proxyTgtReq)
			// Modify Request
			originalDirector := proxyReq.Director
			proxyReq.Director = func(r *http.Request) {
				originalDirector(r)
				r.Header.Set("X-Proxied-By", "Securbase-Access-Plugin")
				r.Header.Set("X-Original-Host", req.Host)
				r.Header.Set("X-Proxy-Timestamp", proxyTimeBegin)

				r.Header.Set("X-PRIVATE-KEY-COMPONENT", apiResult.PrivateKeyComponent)
				r.Header.Set("X-PRIVATE-KEY-COMPONENT-SIZE", apiResult.PrivateKeyComponentSize)
				r.Header.Set("X-PRIVATE-KEY-COMPONENT-PREVIO", apiResult.PrivateKeyComponentPrevio)
				r.Header.Set("X-PRIVATE-KEY-COMPONENT-SIZE-PREVIO", apiResult.PrivateKeyComponentPrevioSize)

				r.Header.Set("X-ORGANIZATION", claims["orgId"].(string))
				r.Header.Set("X-CANAL", claims["canal"].(string))
			}

			// Modify Response
			if p.config.Debug {
				proxyReq.ModifyResponse = func(resp *http.Response) error {
					proxyTimeEnd := time.Now().Format(time.RFC3339Nano)
					resp.Header.Set("X-Proxied-By", "Securbase-Access-Plugin")
					resp.Header.Set("X-Original-Host", req.Host)
					resp.Header.Set("X-Proxy-Timestamp-Begin", proxyTimeBegin)
					resp.Header.Set("X-Proxy-Timestamp-End", proxyTimeEnd)
					return nil
				}
			}

			log.Printf("AccessPlugin: ACCESS ALLOW. From '%s' (%s) method '%s' to '[%s]%s'", req.Host, req.RemoteAddr, req.Method, apiResult.Destination, req.RequestURI)
			proxyReq.ServeHTTP(rw, req)

		} else {
			log.Printf("AccessPlugin: ACCESS ALLOW. From '%s' (%s) method '%s' to '['%s']%s'", req.Host, req.RemoteAddr, req.Method, domain, req.RequestURI)
			p.next.ServeHTTP(rw, req)
		}

		return
	}
}
