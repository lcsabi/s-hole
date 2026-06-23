package blocklist

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const cacheMaxAge = 24 * time.Hour

// httpClient has a generous timeout to handle slow mirrors; 256 MB cap prevents
// a runaway download from filling the disk.
var httpClient = &http.Client{Timeout: 60 * time.Second}

const maxBodyBytes = 256 << 20 // 256 MB

// Update downloads (or loads from cache) all lists and replaces the store.
func Update(store *Store, urls []string, cacheDir string) error {
	var all []string
	for _, u := range urls {
		domains, err := fetchList(u, cacheDir)
		if err != nil {
			fmt.Printf("[blocklist] warning: failed to load %s: %v\n", u, err)
			continue
		}
		all = append(all, domains...)
		fmt.Printf("[blocklist] loaded %d domains from %s\n", len(domains), u)
	}
	store.Replace(all)
	fmt.Printf("[blocklist] total blocked domains: %d\n", store.Len())
	return nil
}

func fetchList(url, cacheDir string) ([]string, error) {
	cachePath := filepath.Join(cacheDir, cacheFilename(url))

	if info, err := os.Stat(cachePath); err == nil {
		if time.Since(info.ModTime()) < cacheMaxAge {
			return loadFromFile(cachePath)
		}
	}

	resp, err := httpClient.Get(url) //nolint:gosec // URL comes from operator config
	if err != nil {
		// Fall back to stale cache if download fails.
		if _, statErr := os.Stat(cachePath); statErr == nil {
			fmt.Printf("[blocklist] download failed, using stale cache for %s\n", url)
			return loadFromFile(cachePath)
		}
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Do not write the error-page body to the cache file.
		if _, statErr := os.Stat(cachePath); statErr == nil {
			fmt.Printf("[blocklist] HTTP %d for %s, using stale cache\n", resp.StatusCode, url)
			return loadFromFile(cachePath)
		}
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	f, err := os.Create(cachePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	tee := io.TeeReader(io.LimitReader(resp.Body, maxBodyBytes), f)
	return parseHostsFormat(tee)
}

func loadFromFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseHostsFormat(f)
}

// parseHostsFormat handles both hosts-file format ("0.0.0.0 domain.com")
// and plain domain-per-line format.
func parseHostsFormat(r io.Reader) ([]string, error) {
	var domains []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		switch len(fields) {
		case 1:
			domains = append(domains, fields[0])
		default:
			// hosts format: first field is IP, second is domain
			ip := fields[0]
			if ip == "0.0.0.0" || ip == "127.0.0.1" || ip == "::" {
				domain := fields[1]
				if domain != "localhost" && domain != "0.0.0.0" {
					domains = append(domains, domain)
				}
			}
		}
	}
	return domains, scanner.Err()
}

// cacheFilename converts a URL to a safe filename.
func cacheFilename(url string) string {
	r := strings.NewReplacer("://", "_", "/", "_", ".", "_", "?", "_", "&", "_", "=", "_")
	return "blocklist_" + r.Replace(url) + ".txt"
}
