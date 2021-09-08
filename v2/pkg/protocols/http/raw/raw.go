package raw

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"strings"

	"github.com/projectdiscovery/rawhttp/client"
)

// Request defines a basic HTTP raw request
type Request struct {
	FullURL        string
	Method         string
	Path           string
	Data           string
	Headers        map[string]string
	UnsafeHeaders  client.Headers
	UnsafeRawBytes []byte
}

// Parse raw URL and adjust request accordingly
func parseUrl(rawRequest *Request, rawURL string, baseURL string, unsafe bool) error {
	parsedBaseURL, err := url.Parse(baseURL)
	if err != nil {
		return err
	}
	if strings.HasPrefix(rawURL, "http") {
		parsedURL, err := url.Parse(rawURL)
		if err != nil {
			return err
		}
		if unsafe {
			// In unsafe mode the path should be send to the target as is
			rawRequest.Path = rawURL
			// Unsafe requests always go to the target host
			rawRequest.FullURL = fmt.Sprintf("%s://%s/%s", parsedBaseURL.Scheme, parsedBaseURL.Host, rawURL)
		} else {
			// URL was fully specified. Use target (host, port) and path from specified URL
			rawRequest.Path = parsedURL.Path
			rawRequest.FullURL = rawURL
		}
		if rawRequest.Headers["Host"] == "" {
			rawRequest.Headers["Host"] = parsedURL.Host
		}
	} else {
		// Assume given url is relative to base URL
		rawRequest.Path = strings.ReplaceAll(
			fmt.Sprintf("%s%s", parsedBaseURL.Path, rawURL),
			"//", "/",
		)
		rawRequest.FullURL = fmt.Sprintf("%s://%s%s", parsedBaseURL.Scheme, parsedBaseURL.Host, rawRequest.Path)
		if rawRequest.Headers["Host"] == "" {
			rawRequest.Headers["Host"] = parsedBaseURL.Host
		}
	}
	return nil
}

// Parse parses the raw request as supplied by the user
func Parse(request, baseURL string, unsafe bool) (*Request, error) {
	rawRequest := &Request{
		Headers: make(map[string]string),
	}
	if unsafe {
		request = strings.ReplaceAll(request, "\\0", "\x00")
		request = strings.ReplaceAll(request, "\\r", "\r")
		request = strings.ReplaceAll(request, "\\n", "\n")
		rawRequest.UnsafeRawBytes = []byte(request)
	}
	reader := bufio.NewReader(strings.NewReader(request))
	s, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("could not read request: %s", err)
	}

	parts := strings.Split(s, " ")
	if len(parts) < 3 && !unsafe {
		return nil, fmt.Errorf("malformed request supplied")
	}
	// Set the request Method
	rawRequest.Method = parts[0]

	var mutlipartRequest bool
	// Accepts all malformed headers
	var key, value string
	for {
		line, readErr := reader.ReadString('\n')
		line = strings.TrimSpace(line)

		if readErr != nil || line == "" {
			if readErr != io.EOF {
				break
			}
		}

		p := strings.SplitN(line, ":", 2)
		key = p[0]
		if len(p) > 1 {
			value = p[1]
		}
		if strings.Contains(key, "Content-Type") && strings.Contains(value, "multipart/") {
			mutlipartRequest = true
		}

		// in case of unsafe requests multiple headers should be accepted
		// therefore use the full line as key
		_, found := rawRequest.Headers[key]
		if unsafe {
			rawRequest.UnsafeHeaders = append(rawRequest.UnsafeHeaders, client.Header{Key: line})
		}

		if unsafe && found {
			rawRequest.Headers[line] = ""
		} else {
			rawRequest.Headers[key] = strings.TrimSpace(value)
		}
		if readErr == io.EOF {
			break
		}
	}

	if err := parseUrl(rawRequest, parts[1], baseURL, unsafe); err != nil {
		return nil, fmt.Errorf("could not parse URL: %s", err)
	}

	// Set the request body
	b, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("could not read request body: %s", err)
	}
	rawRequest.Data = string(b)
	if !mutlipartRequest {
		rawRequest.Data = strings.TrimSuffix(rawRequest.Data, "\r\n")
	}
	return rawRequest, nil
}
