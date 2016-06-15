package main

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/pyke369/golang-support/uconfig"
	"github.com/pyke369/golang-support/ulog"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const progname = "xupload"
const version = "3.0.1"

var (
	showHelp                                     = flag.Bool("help", false, "Display help and exit")
	showVersion                                  = flag.Bool("version", false, "Display version and exit")
	config                                       *uconfig.UConfig
	logger                                       *ulog.ULog
	incomingPath, outgoingEndpoint, outgoingPath string
	startup, maxAge                              time.Time
	maxSpace, totalCount, completeCount          int64
	outgoingCount, outgoingSize                  int64
	sessions                                     *Sessions      = NewSessions()
	uuidMatcher                                  *regexp.Regexp = regexp.MustCompile("^[0-9a-f]{32}$")
	rangeMatcher                                 *regexp.Regexp = regexp.MustCompile("^bytes\\s+(\\d+)-(\\d+)?/(\\d+)$")
	dispositionMatcher                           *regexp.Regexp = regexp.MustCompile("filename=\"?([^\";]+)")
)

func crossdomainHandler(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "text/xml")
	response.Write([]byte("<?xml version=\"1.0\"?>\n" +
		"<!DOCTYPE cross-domain-policy SYSTEM \"http://www.macromedia.com/xml/dtds/cross-domain-policy.dtd\">\n" +
		"<cross-domain-policy>\n" +
		"  <site-control permitted-cross-domain-policies=\"master-only\"/>\n" +
		"  <allow-access-from domain=\"*\"/>\n" +
		"</cross-domain-policy>\n"))
}

func startupHandler(next http.Handler, methods []string) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Server", fmt.Sprintf("%s/%s", progname, version))
		response.Header().Set("Access-Control-Allow-Origin", "*")
		response.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Range, Content-Disposition, Content-Description, Session-ID")
		if methods != nil {
			response.Header().Set("Access-Control-Allow-Methods", strings.Join(methods, ", "))
		}
		if request.Method == "OPTIONS" {
			return
		}
		if methods != nil {
			var found bool = false
			for _, method := range methods {
				if method == request.Method {
					found = true
					break
				}
			}
			if !found {
				response.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
		}
		if remote, port, err := net.SplitHostPort(request.RemoteAddr); err == nil {
			if remote := net.ParseIP(remote); remote != nil {
				if forwarded := request.Header.Get("X-Forwarded-For"); forwarded != "" {
					for _, forwarder := range config.GetPaths("server.forwarders") {
						forwarder = config.GetString(forwarder, "")
						if strings.Index(forwarder, "/") < 0 {
							forwarder += "/32"
						}
						if _, network, err := net.ParseCIDR(forwarder); err == nil {
							if network.Contains(remote) {
								for _, client := range strings.Split(forwarded, ", ") {
									if client := net.ParseIP(client); client != nil {
										request.RemoteAddr = fmt.Sprintf("%s:%s", client, port)
										break
									}
								}
								return
							}
						}
					}
				}
			}
		}
		next.ServeHTTP(response, request)
	})
}

func authHandler(next http.Handler, path string) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		check := false
		if remote, _, err := net.SplitHostPort(request.RemoteAddr); err == nil {
			if remote := net.ParseIP(remote); remote != nil {
				for _, allow := range config.GetPaths(path + ".allow") {
					check = true
					allow = config.GetString(allow, "")
					if strings.Index(allow, "/") < 0 {
						allow += "/32"
					}
					if _, network, err := net.ParseCIDR(allow); err == nil {
						if remote != nil && network.Contains(remote) {
							next.ServeHTTP(response, request)
							return
						}
					}
				}
			}
		}
		credentials := ""
		if username, password, ok := request.BasicAuth(); ok {
			credentials = fmt.Sprintf("%s:%s", username, password)
		}
		for _, auth := range config.GetPaths(path + ".auth") {
			check = true
			if config.GetString(auth, "") == credentials {
				next.ServeHTTP(response, request)
				return
			}
		}
		if check {
			response.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=\"%s\"", progname))
			response.WriteHeader(http.StatusUnauthorized)
		} else {
			next.ServeHTTP(response, request)
		}
	})
}

func sendResponse(response http.ResponseWriter, request *http.Request, fields map[string]string, status int) {
	seal := ""
	if secret := config.GetString("incoming.secret", ""); secret != "" {
		var keys []string
		for key := range fields {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		input := ""
		for _, key := range keys {
			input += fmt.Sprintf("%s%s", key, fields[key])
		}
		seal = fmt.Sprintf("%x", md5.Sum([]byte(input+secret)))
	}

	values := url.Values{}
	if seal != "" {
		values.Set("seal", seal)
	}
	for key, value := range fields {
		if key != "url" {
			values.Set(key, value)
		}
	}
	xform := fmt.Sprintf("#%s", base64.StdEncoding.EncodeToString([]byte(values.Encode())))

	parameters, _ := url.ParseQuery(request.URL.RawQuery)
	if target := parameters.Get("target"); target != "" {
		targetURL, _ := url.Parse(target)
		values := targetURL.Query()
		if seal != "" {
			values.Set("seal", seal)
		}
		for key, value := range fields {
			if key == "url" {
				values.Set(key, value+xform)
			} else {
				values.Set(key, value)
			}
		}
		target = fmt.Sprintf("%s://%s%s?%s", targetURL.Scheme, targetURL.Host, targetURL.Path, values.Encode())
		http.Redirect(response, request, target, http.StatusFound)
	} else {
		response.Header().Set("Content-Type", "application/json")
		if seal != "" {
			fields["seal"] = seal
		}
		if fields["url"] != "" {
			fields["url"] += xform
		}
		json, _ := json.Marshal(fields)
		response.WriteHeader(status)
		response.Write(json)
	}
}

func incomingHandler(response http.ResponseWriter, request *http.Request) {
	parameters, _ := url.ParseQuery(request.URL.RawQuery)

	uuid := parameters.Get("uuid")
	if !uuidMatcher.MatchString(uuid) {
		sendResponse(response, request, map[string]string{"error": "invalid uuid"}, http.StatusOK)
		return
	}

	if config.GetString("incoming.secret", "") != "" {
		input := ""
		for _, key := range [3]string{"maxsize", "target", "uuid"} {
			if value := parameters.Get(key); value != "" {
				input += fmt.Sprintf("%s%s", key, value)
			}
		}
		if parameters.Get("seal") != fmt.Sprintf("%x", md5.Sum([]byte(input+config.GetString("incoming.secret", "")))) {
			sendResponse(response, request, map[string]string{"error": "invalid security seal"}, http.StatusOK)
			return
		}
	}

	maxSize := config.GetSize("incoming.maxsize", 2*1024*1024)
	if parameters.Get("maxsize") != "" {
		limit, _ := strconv.ParseFloat(parameters.Get("maxsize"), 64)
		maxSize = int64(math.Min(limit*1024*1024, float64(maxSize)))
	}

	multipart, err := request.MultipartReader()
	if err == nil {
		session := sessions.Get(uuid)
		if session != nil {
			sendResponse(response, request, map[string]string{"error": "upload session already in use"}, http.StatusOK)
			return
		}
		size, _ := strconv.ParseInt(request.Header.Get("Content-Length"), 10, 64)
		if size == 0 || size >= maxSize {
			sendResponse(response, request, map[string]string{"error": "content too large"}, http.StatusOK)
			return
		}
		for {
			part, err := multipart.NextPart()
			if err != nil {
				break
			}
			if part.FormName() == "file" {
				name := filepath.Base(part.FileName())
				if filepath.Ext(name) == "" {
					sendResponse(response, request, map[string]string{"error": "missing filename extension"}, http.StatusOK)
					return
				}
				session = sessions.Set(uuid, &Session{
					start:    time.Now(),
					last:     time.Now(),
					name:     strings.Replace(strings.TrimSuffix(name, filepath.Ext(name)), "%", "", -1),
					path:     fmt.Sprintf("%s/%s%s", incomingPath, uuid, strings.ToLower(filepath.Ext(name))),
					size:     size,
					checksum: sha1.New(),
				})
				totalCount++
				handle, err := os.OpenFile(session.path, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
				if err != nil {
					session.state = STATE_ERROR
					session.errmsg = "cannot create destination"
					sendResponse(response, request, map[string]string{"error": session.errmsg}, http.StatusOK)
					return
				}
				defer handle.Close()
				block := make([]byte, 64*1024)
				for {
					read, err := io.ReadAtLeast(part, block, len(block))
					if read > 0 {
						session.state = STATE_UPLOADING
						session.last = time.Now()
						if _, err := handle.Write(block[0:read]); err != nil {
							session.state = STATE_ERROR
							session.errmsg = "cannot append to destination"
							sendResponse(response, request, map[string]string{"error": session.errmsg}, http.StatusOK)
							logger.Info(map[string]interface{}{"type": "incoming", "error": session.errmsg, "remote": request.RemoteAddr,
								"uuid": uuid, "name": session.name, "size": session.size, "received": session.received})
							return
						}
						session.received += int64(read)
						session.checksum.Write(block[0:read])
					}
					if err != nil {
						if err.Error() != "EOF" && err.Error() != "unexpected EOF" {
							session.state = STATE_ERROR
							session.errmsg = "incomplete content"
							sendResponse(response, request, map[string]string{"error": session.errmsg}, http.StatusOK)
							logger.Info(map[string]interface{}{"type": "incoming", "error": session.errmsg, "remote": request.RemoteAddr,
								"uuid": uuid, "name": session.name, "size": session.size, "received": session.received})
							return
						}
						session.size = session.received
						break
					}
				}

				protocol := "http"
				if request.TLS != nil {
					protocol += "s"
				}
				fields := map[string]string{
					"name": session.name,
					"size": fmt.Sprintf("%d", session.size),
					"url":  fmt.Sprintf("%s://%s%s/%s", protocol, request.Host, outgoingEndpoint, filepath.Base(session.path)),
					"hash": fmt.Sprintf("%x", session.checksum.Sum(nil)),
				}
				postexec := config.GetString("incoming.postexec", "")
				if postexec != "" {
					postexec = strings.Replace(postexec, "{{file}}", session.path, -1)
					arguments := strings.Split(postexec, " ")
					if content, err := exec.Command(arguments[0], arguments[1:]...).Output(); err == nil {
						for _, line := range strings.Split(string(content), "\n") {
							if values := strings.Split(line, "="); len(values) >= 2 {
								fields[values[0]] = values[1]
							}
						}
					}
				}
				os.Rename(session.path, fmt.Sprintf("%s/%s", outgoingPath, filepath.Base(session.path)))

				session.state = STATE_DONE
				completeCount++
				sendResponse(response, request, fields, http.StatusOK)
				duration := math.Max(0.001, math.Trunc(float64(session.last.Sub(session.start))/float64(time.Millisecond))/1000)
				throughput := math.Trunc(((float64(session.received)/duration)*8)/1000) / 1000
				logger.Info(map[string]interface{}{"type": "incoming", "remote": request.RemoteAddr, "uuid": uuid, "name": session.name, "size": session.size,
					"received": session.received, "duration": duration, "throughput": throughput, "hash": fmt.Sprintf("%x", session.checksum.Sum(nil))})
				return
			}
		}
	} else {
		length, _ := strconv.ParseInt(request.Header.Get("Content-Length"), 10, 64)
		matcher := rangeMatcher.FindStringSubmatch(request.Header.Get("Content-Range"))
		start := int64(0)
		end := int64(0)
		size := int64(0)
		if matcher == nil {
			start = 0
			end = length - 1
			size = length
		} else {
			start, _ = strconv.ParseInt(matcher[1], 10, 64)
			end, _ = strconv.ParseInt(matcher[2], 10, 64)
			size, _ = strconv.ParseInt(matcher[3], 10, 64)
			if end == 0 {
				end = size - 1
			}
		}
		if size <= 0 || start > end || start < 0 || start >= size || end < 0 || end >= size || length != (end-start+1) {
			sendResponse(response, request, map[string]string{"error": "invalid content range"}, http.StatusBadRequest)
			return
		}

		session := sessions.Get(uuid)
		if session != nil {
			if !session.resumeable {
				sendResponse(response, request, map[string]string{"error": "upload session already in use"}, http.StatusBadRequest)
				return
			}
		} else {
			if size >= maxSize {
				sendResponse(response, request, map[string]string{"error": "content too large"}, http.StatusBadRequest)
				return
			}
			matcher := dispositionMatcher.FindStringSubmatch(request.Header.Get("Content-Disposition"))
			if matcher == nil {
				sendResponse(response, request, map[string]string{"error": "missing filename"}, http.StatusBadRequest)
				return
			}
			name, _ := url.QueryUnescape(filepath.Base(matcher[1]))
			name = strings.Replace(name, "%", "", -1)
			if filepath.Ext(name) == "" {
				sendResponse(response, request, map[string]string{"error": "missing filename extension"}, http.StatusBadRequest)
				return
			}
			session = sessions.Set(uuid, &Session{
				resumeable: true,
				start:      time.Now(),
				last:       time.Now(),
				name:       strings.TrimSuffix(name, filepath.Ext(name)),
				path:       fmt.Sprintf("%s/%s%s", incomingPath, uuid, strings.ToLower(filepath.Ext(name))),
				size:       size,
				checksum:   sha1.New(),
			})
			if info, err := os.Stat(session.path); err == nil {
				session.received = info.Size()
				session.start = info.ModTime()
				if handle, err := os.OpenFile(session.path, os.O_RDONLY, 0644); err == nil {
					block := make([]byte, 1024*1024)
					for {
						read, err := handle.Read(block)
						if read > 0 {
							session.checksum.Write(block[0:read])
						}
						if err != nil {
							break
						}
					}
					handle.Close()
				}
			} else {
				totalCount++
			}
		}
		if size != session.size || start != session.received || (session.received+length) > session.size {
			session.state = STATE_ERROR
			session.errmsg = "content range sequence error"
			response.Header().Set("Range", fmt.Sprintf("0-%.0f/%d", math.Max(float64(session.received), 1)-1, session.size))
			sendResponse(response, request, map[string]string{"error": session.errmsg}, http.StatusBadRequest)
			return
		}

		handle, err := os.OpenFile(session.path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
		if err != nil {
			session.state = STATE_ERROR
			session.errmsg = "cannot create destination"
			sendResponse(response, request, map[string]string{"error": session.errmsg}, http.StatusBadRequest)
			return
		}
		defer handle.Close()
		block := make([]byte, 64*1024)
		received := int64(0)
		now := time.Now()
		for {
			read, err := io.ReadAtLeast(request.Body, block, len(block))
			if read > 0 {
				session.state = STATE_UPLOADING
				session.last = time.Now()
				if received+int64(read) > length {
					read = int(length - received)
				}
				if _, err := handle.WriteAt(block[0:read], int64(session.received)); err != nil {
					session.state = STATE_ERROR
					session.errmsg = "cannot append to destination"
					sendResponse(response, request, map[string]string{"error": session.errmsg}, http.StatusBadRequest)
					logger.Info(map[string]interface{}{"type": "incoming", "error": session.errmsg, "remote": request.RemoteAddr,
						"uuid": uuid, "name": session.name, "size": session.size, "start": start, "received": received})
					return
				}
				session.received += int64(read)
				received += int64(read)
				session.checksum.Write(block[0:read])
			}
			if err != nil || received == length {
				break
			}
		}
		if received < length {
			session.state = STATE_ERROR
			session.errmsg = "incomplete content"
			sendResponse(response, request, map[string]string{"error": session.errmsg}, http.StatusBadRequest)
			logger.Info(map[string]interface{}{"type": "incoming", "error": session.errmsg, "remote": request.RemoteAddr,
				"uuid": uuid, "name": session.name, "size": session.size, "start": start, "received": received})
			return
		}

		if session.received < session.size {
			crange := fmt.Sprintf("0-%.0f/%d", math.Max(float64(session.received), 1)-1, session.size)
			response.Header().Set("Range", crange)
			http.Error(response, crange+"\n", http.StatusCreated)
			duration := math.Max(0.001, math.Trunc(float64(time.Since(now))/float64(time.Millisecond))/1000)
			throughput := math.Trunc(((float64(received)/duration)*8)/1000) / 1000
			logger.Info(map[string]interface{}{"type": "incoming", "remote": request.RemoteAddr, "uuid": uuid, "name": session.name,
				"size": size, "start": start, "received": received, "duration": duration, "throughput": throughput})
		} else {
			protocol := "http"
			if request.TLS != nil {
				protocol += "s"
			}
			fields := map[string]string{
				"name": session.name,
				"size": fmt.Sprintf("%d", session.size),
				"url":  fmt.Sprintf("%s://%s%s/%s", protocol, request.Host, outgoingEndpoint, filepath.Base(session.path)),
				"hash": fmt.Sprintf("%x", session.checksum.Sum(nil)),
			}
			postexec := config.GetString("incoming.postexec", "")
			if postexec != "" {
				postexec = strings.Replace(postexec, "{{file}}", session.path, -1)
				arguments := strings.Split(postexec, " ")
				if content, err := exec.Command(arguments[0], arguments[1:]...).Output(); err == nil {
					for _, line := range strings.Split(string(content), "\n") {
						if values := strings.Split(line, "="); len(values) >= 2 {
							fields[values[0]] = values[1]
						}
					}
				}
			}
			os.Rename(session.path, fmt.Sprintf("%s/%s", outgoingPath, filepath.Base(session.path)))

			session.state = STATE_DONE
			completeCount++
			sendResponse(response, request, fields, http.StatusOK)
			duration := math.Max(0.001, math.Trunc(float64(session.last.Sub(session.start))/float64(time.Millisecond))/1000)
			throughput := math.Trunc(((float64(session.received)/duration)*8)/1000) / 1000
			logger.Info(map[string]interface{}{"type": "incoming", "remote": request.RemoteAddr, "uuid": uuid, "name": session.name, "size": session.size,
				"start": start, "received": session.received, "duration": duration, "throughput": throughput, "hash": fmt.Sprintf("%x", session.checksum.Sum(nil))})
		}
		return
	}
	sendResponse(response, request, map[string]string{"error": "missing content"}, http.StatusOK)
}

func outgoingHandler(response http.ResponseWriter, request *http.Request) {
	path := fmt.Sprintf("%s%s", outgoingPath, strings.TrimPrefix(request.URL.Path, outgoingEndpoint))
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		response.WriteHeader(http.StatusNotFound)
		return
	}
	now := time.Now()
	http.ServeFile(response, request, path)
	sent, _ := strconv.ParseInt(response.Header().Get("Content-Length"), 10, 64)
	if request.Method == "HEAD" {
		sent = 0
	}
	duration := math.Max(0.001, math.Trunc(float64(time.Since(now))/float64(time.Millisecond))/1000)
	throughput := math.Trunc(((float64(sent)/duration)*8)/1000) / 1000
	logger.Info(map[string]interface{}{"type": "outgoing", "remote": request.RemoteAddr, "document": filepath.Base(path),
		"size": info.Size(), "sent": sent, "duration": duration, "throughput": throughput})
}

func progressHandler(response http.ResponseWriter, request *http.Request) {
	fields := map[string]interface{}{
		"state": "starting",
	}
	parameters, _ := url.ParseQuery(request.URL.RawQuery)
	if session := sessions.Get(parameters.Get("uuid")); session != nil {
		switch session.state {
		case STATE_UPLOADING:
			fields["state"] = "uploading"
			fields["size"] = int64(session.size)
			fields["received"] = int64(session.received)
		case STATE_DONE:
			fields["state"] = "done"
		case STATE_ERROR:
			fields["state"] = "error"
			fields["error"] = session.errmsg
		}
	}
	json, _ := json.Marshal(fields)
	callback := parameters.Get("jsonp")
	if callback == "" {
		callback = parameters.Get("callback")
	}
	if callback == "" {
		response.Header().Set("Content-Type", "application/json")
		response.Write(json)
	} else {
		response.Header().Set("Content-Type", "text/javascript")
		response.Write([]byte(fmt.Sprintf("%s(%s);\n", callback, json)))
	}
}

func age(seconds int64) string {
	age := []string{}

	if days := seconds / 86400; days != 0 {
		age = append(age, fmt.Sprintf("%dd", days))
		seconds -= days * 86400
	}
	if hours := seconds / 3600; hours != 0 {
		age = append(age, fmt.Sprintf("%dh", hours))
		seconds -= hours * 3600
	}
	if minutes := seconds / 60; minutes != 0 {
		age = append(age, fmt.Sprintf("%dmn", minutes))
		seconds -= minutes * 60
	}
	age = append(age, fmt.Sprintf("%ds", seconds))
	return strings.Join(age, "")
}

func monitorHandler(response http.ResponseWriter, request *http.Request) {
	counts := [2]int64{0, 0}
	sizes := [2]int64{0, 0}
	for _, key := range sessions.Keys() {
		session := sessions.Get(key)
		if session.state == STATE_UPLOADING {
			index := 0
			if session.resumeable {
				index = 1
			}
			counts[index]++
			sizes[index] += session.received
		}
	}
	output := map[string]interface{}{
		"server": map[string]interface{}{
			"version": version,
			"uptime":  age(int64(time.Since(startup)) / int64(time.Second)),
		},
		"incoming": map[string]interface{}{
			"path":     incomingPath,
			"total":    totalCount,
			"complete": completeCount,
			"count":    counts[0] + counts[1],
			"size":     (sizes[0] + sizes[1]) / (1024 * 1024),
			"progressive": map[string]interface{}{
				"count": counts[0],
				"size":  sizes[0] / (1024 * 1024),
			},
			"resumeable": map[string]interface{}{
				"count": counts[1],
				"size":  sizes[1] / (1024 * 1024),
			},
		},
		"outgoing": map[string]interface{}{
			"path":     outgoingPath,
			"maxspace": maxSpace / (1024 * 1024),
			"maxage":   age(int64(time.Since(maxAge)) / int64(time.Second)),
			"count":    outgoingCount,
			"size":     outgoingSize / (1024 * 1024),
		},
	}
	response.Header().Set("Content-Type", "application/json")
	if json, err := json.Marshal(output); err == nil {
		response.Write(json)
	}
}

type Document struct {
	path           string
	size, modified int64
}

type ByAge []Document

func (a ByAge) Len() int           { return len(a) }
func (a ByAge) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByAge) Less(i, j int) bool { return a[i].modified < a[j].modified }

func garbageCollector(now time.Time) {
	maxAge = now
	cleanupProgressive := config.GetDurationBounds("incoming.cleanup.progressive", 5*60, 60, 15*60)
	cleanupResumeable := config.GetDurationBounds("incoming.cleanup.resumeable", 12*3600, 1*3600, 24*3600)
	cleanupDone := config.GetDurationBounds("incoming.cleanup.done", 30, 10, 60)
	sessions.Cleanup(int64(cleanupProgressive), int64(cleanupResumeable), int64(cleanupDone))
	filepath.Walk(incomingPath, func(path string, info os.FileInfo, err error) error {
		if info.Mode().IsRegular() && now.Sub(info.ModTime()) >= (time.Second*time.Duration(math.Max(cleanupProgressive, cleanupResumeable))) {
			os.Remove(path)
			logger.Info(map[string]interface{}{"type": "garbage", "path": "incoming", "document": info.Name(),
				"size": info.Size(), "age": age(int64(now.Sub(info.ModTime())) / int64(time.Second))})
		}
		return nil
	})
	size := int64(0)
	documents := []Document{}
	filepath.Walk(outgoingPath, func(path string, info os.FileInfo, err error) error {
		if info.Mode().IsRegular() {
			size += info.Size()
			documents = append(documents, Document{path: path, size: info.Size(), modified: info.ModTime().Unix()})
			if info.ModTime().Before(maxAge) {
				maxAge = info.ModTime()
			}
		}
		return nil
	})
	outgoingSize = size
	outgoingCount = int64(len(documents))
	if size > maxSpace {
		sort.Sort(ByAge(documents))
		deleted := int64(0)
		for _, document := range documents {
			os.Remove(document.path)
			outgoingCount--
			logger.Info(map[string]interface{}{"type": "garbage", "path": "outgoing", "document": filepath.Base(document.path),
				"size": document.size, "age": age(now.Unix() - document.modified)})
			deleted += document.size
			if deleted >= size-maxSpace {
				break
			}
		}
	}
}

func main() {
	flag.Parse()
	if *showHelp {
		fmt.Fprintf(os.Stderr, "Usage: %s [-help] [-version] [<configuration file>]\n", filepath.Base(os.Args[0]))
		os.Exit(0)
	}
	if *showVersion {
		fmt.Fprintf(os.Stderr, "%s\n", version)
		os.Exit(0)
	}
	if len(flag.Args()) < 1 {
		fmt.Fprintf(os.Stderr, "missing configuration file - aborting\n")
		os.Exit(1)
	}

	var err error
	if config, err = uconfig.New(flag.Args()[0]); err != nil {
		fmt.Fprintf(os.Stderr, "configuration file syntax error: %s - aborting\n", err)
		os.Exit(2)
	}

	incomingPath = strings.TrimRight(config.GetString("incoming.path", fmt.Sprintf("/var/run/%s/incoming", progname)), "/")
	os.MkdirAll(incomingPath, 0755)
	outgoingPath = strings.TrimRight(config.GetString("outgoing.path", fmt.Sprintf("/var/run/%s/outgoing", progname)), "/")
	os.MkdirAll(outgoingPath, 0755)
	maxSpace = config.GetSizeBounds("outgoing.maxspace", 64*1024*1024, 2*1024*1024, math.MaxInt64)

	logger = ulog.New(config.GetString("server.log", "console()"))
	logger.Info(map[string]interface{}{"type": "start", "version": version, "config": flag.Args()[0], "incoming": incomingPath, "outgoing": outgoingPath})
	startup = time.Now()
	garbageCollector(startup)

	aliases := false
	for _, path := range config.GetPaths("incoming.endpoint") {
		http.Handle(strings.TrimRight(config.GetString(path, "/upload"), "/"),
			startupHandler(authHandler(http.HandlerFunc(incomingHandler), "incoming.acl"), []string{"POST"}))
		aliases = true
	}
	if !aliases {
		http.Handle(strings.TrimRight(config.GetString("incoming.endpoint", "/upload"), "/"),
			startupHandler(authHandler(http.HandlerFunc(incomingHandler), "incoming.acl"), []string{"POST"}))
	}
	outgoingEndpoint = strings.TrimRight(config.GetString("outgoing.endpoint", "/download"), "/")
	http.Handle(outgoingEndpoint+"/", startupHandler(authHandler(http.HandlerFunc(outgoingHandler), "outgoing.acl"), []string{"HEAD", "GET"}))
	http.Handle(strings.TrimRight(config.GetString("progress.endpoint", "/progress"), "/"),
		startupHandler(authHandler(http.HandlerFunc(progressHandler), "progress.acl"), []string{"GET"}))
	http.Handle(strings.TrimRight(config.GetString("monitor.endpoint", "/monitor"), "/"),
		startupHandler(authHandler(http.HandlerFunc(monitorHandler), "monitor.acl"), []string{"HEAD", "GET"}))

	http.Handle("/crossdomain.xml", startupHandler(http.HandlerFunc(crossdomainHandler), []string{"GET"}))
	http.Handle("/", startupHandler(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) { response.WriteHeader(http.StatusNotFound) }), nil))

	for _, path := range config.GetPaths("server.listen") {
		if parts := strings.Split(config.GetStringMatch(path, "_", "^(?:\\*|\\d+(?:\\.\\d+){3}|\\[[^\\]]+\\])(?::\\d+)?(?:(?:,[^,]+){2})?$"), ","); parts[0] != "_" {
			server := &http.Server{
				Addr:        strings.TrimLeft(parts[0], "*"),
				ReadTimeout: 60 * time.Second,
			}
			if len(parts) > 1 {
				go server.ListenAndServeTLS(parts[1], parts[2])
			} else {
				go server.ListenAndServe()
			}
		}
	}

	for now := range time.Tick(15 * time.Second) {
		garbageCollector(now)
	}
}
