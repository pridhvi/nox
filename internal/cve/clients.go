package cve

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

type HTTPClient struct {
	name    string
	baseURL string
	client  *http.Client
}

func NewNVDClient(client *http.Client, baseURL string) HTTPClient {
	return newHTTPClient("nvd", client, firstNonEmpty(baseURL, "https://services.nvd.nist.gov/rest/json/cves/2.0"))
}

func NewOSVClient(client *http.Client, baseURL string) HTTPClient {
	return newHTTPClient("osv", client, firstNonEmpty(baseURL, "https://api.osv.dev/v1/query"))
}

func NewCIRCLClient(client *http.Client, baseURL string) HTTPClient {
	return newHTTPClient("circl", client, firstNonEmpty(baseURL, "https://cve.circl.lu/api/search"))
}

func NewVulnersClient(client *http.Client, baseURL string) HTTPClient {
	return newHTTPClient("vulners", client, firstNonEmpty(baseURL, "https://vulners.com/api/v3/search/lucene/"))
}

func NewGitHubAdvisoryClient(client *http.Client, baseURL string) HTTPClient {
	return newHTTPClient("github-advisories", client, firstNonEmpty(baseURL, "https://api.github.com/advisories"))
}

func newHTTPClient(name string, client *http.Client, baseURL string) HTTPClient {
	if client == nil {
		client = http.DefaultClient
	}
	return HTTPClient{name: name, baseURL: baseURL, client: client}
}

func (c HTTPClient) Name() string { return c.name }

func (c HTTPClient) Search(ctx context.Context, product, version string) ([]Advisory, error) {
	switch c.name {
	case "nvd":
		return c.searchNVD(ctx, product, version)
	case "osv":
		return c.searchOSV(ctx, product, version)
	case "github-advisories":
		return c.searchGitHubAdvisories(ctx, product, version)
	case "circl":
		return c.searchCIRCL(ctx, product, version)
	case "vulners":
		return c.searchVulners(ctx, product, version)
	default:
		return nil, nil
	}
}

func (c HTTPClient) searchNVD(ctx context.Context, product, version string) ([]Advisory, error) {
	endpoint, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, err
	}
	query := endpoint.Query()
	query.Set("keywordSearch", product+" "+version)
	endpoint.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var body struct {
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics struct {
					CVSSMetricV31 []struct {
						CVSSData struct {
							BaseScore    float64 `json:"baseScore"`
							VectorString string  `json:"vectorString"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
				} `json:"metrics"`
				References struct {
					ReferenceData []struct {
						URL string `json:"url"`
					} `json:"referenceData"`
				} `json:"references"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	var advisories []Advisory
	for _, item := range body.Vulnerabilities {
		advisory := Advisory{
			CVEID:           item.CVE.ID,
			Product:         product,
			AffectedVersion: version,
			Source:          c.name,
		}
		for _, description := range item.CVE.Descriptions {
			if description.Lang == "en" {
				advisory.Description = description.Value
				break
			}
		}
		if len(item.CVE.Metrics.CVSSMetricV31) > 0 {
			advisory.CVSSv3Score = item.CVE.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
			advisory.CVSSv3Vector = item.CVE.Metrics.CVSSMetricV31[0].CVSSData.VectorString
		}
		for _, ref := range item.CVE.References.ReferenceData {
			advisory.References = append(advisory.References, ref.URL)
		}
		advisories = append(advisories, advisory)
	}
	return advisories, nil
}

func (c HTTPClient) searchOSV(ctx context.Context, product, version string) ([]Advisory, error) {
	payload := map[string]any{
		"version": version,
		"package": map[string]string{
			"name": product,
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, nil
	}
	var parsed struct {
		Vulns []struct {
			ID         string   `json:"id"`
			Summary    string   `json:"summary"`
			Details    string   `json:"details"`
			Modified   string   `json:"modified"`
			Aliases    []string `json:"aliases"`
			References []struct {
				Type string `json:"type"`
				URL  string `json:"url"`
			} `json:"references"`
			Affected []struct {
				Package struct {
					Name string `json:"name"`
				} `json:"package"`
				Ranges []struct {
					Events []struct {
						Introduced string `json:"introduced"`
						Fixed      string `json:"fixed"`
					} `json:"events"`
				} `json:"ranges"`
			} `json:"affected"`
		} `json:"vulns"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}
	var advisories []Advisory
	for _, vuln := range parsed.Vulns {
		cveID := firstCVE(strings.Join(append([]string{vuln.ID}, vuln.Aliases...), " "))
		if cveID == "" {
			continue
		}
		advisory := Advisory{
			CVEID:           cveID,
			Product:         product,
			AffectedVersion: version,
			Description:     firstNonEmpty(vuln.Summary, vuln.Details),
			Source:          c.name,
		}
		for _, affected := range vuln.Affected {
			if affected.Package.Name != "" {
				advisory.Product = affected.Package.Name
			}
			for _, rng := range affected.Ranges {
				for _, event := range rng.Events {
					if event.Fixed != "" && advisory.FixedVersion == "" {
						advisory.FixedVersion = event.Fixed
						advisory.PatchAvailable = true
					}
				}
			}
		}
		for _, ref := range vuln.References {
			advisory.References = append(advisory.References, ref.URL)
			if strings.Contains(strings.ToLower(ref.Type+" "+ref.URL), "exploit") {
				advisory.ExploitAvailable = true
			}
		}
		advisories = append(advisories, advisory)
	}
	return advisories, nil
}

func (c HTTPClient) searchGitHubAdvisories(ctx context.Context, product, version string) ([]Advisory, error) {
	endpoint, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, err
	}
	query := endpoint.Query()
	query.Set("query", product+" "+version)
	endpoint.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, nil
	}
	var parsed []struct {
		GHSAID          string `json:"ghsa_id"`
		CVEID           string `json:"cve_id"`
		Summary         string `json:"summary"`
		Description     string `json:"description"`
		Severity        string `json:"severity"`
		HTMLURL         string `json:"html_url"`
		Vulnerabilities []struct {
			Package struct {
				Name string `json:"name"`
			} `json:"package"`
			VulnerableVersionRange string `json:"vulnerable_version_range"`
			FirstPatchedVersion    struct {
				Identifier string `json:"identifier"`
			} `json:"first_patched_version"`
		} `json:"vulnerabilities"`
		CVSS struct {
			Score        float64 `json:"score"`
			VectorString string  `json:"vector_string"`
		} `json:"cvss"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}
	var advisories []Advisory
	for _, item := range parsed {
		cveID := firstNonEmpty(item.CVEID, firstCVE(item.Summary+" "+item.Description))
		if cveID == "" {
			continue
		}
		advisory := Advisory{
			CVEID:        cveID,
			Product:      product,
			CVSSv3Score:  item.CVSS.Score,
			CVSSv3Vector: item.CVSS.VectorString,
			Description:  firstNonEmpty(item.Summary, item.Description),
			References:   compactStrings([]string{item.HTMLURL}),
			Source:       c.name,
		}
		for _, vuln := range item.Vulnerabilities {
			if vuln.Package.Name != "" {
				advisory.Product = vuln.Package.Name
			}
			advisory.AffectedVersion = firstNonEmpty(vuln.VulnerableVersionRange, version)
			if vuln.FirstPatchedVersion.Identifier != "" {
				advisory.FixedVersion = vuln.FirstPatchedVersion.Identifier
				advisory.PatchAvailable = true
			}
		}
		advisories = append(advisories, advisory)
	}
	return advisories, nil
}

func (c HTTPClient) searchCIRCL(ctx context.Context, product, version string) ([]Advisory, error) {
	endpoint := strings.TrimRight(c.baseURL, "/") + "/" + url.PathEscape(product)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, nil
	}
	var parsed []struct {
		ID                      string   `json:"id"`
		CVE                     string   `json:"cve"`
		Summary                 string   `json:"summary"`
		CVSS                    float64  `json:"cvss"`
		References              []string `json:"references"`
		VulnerableConfiguration []string `json:"vulnerable_configuration"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}
	var advisories []Advisory
	for _, item := range parsed {
		cveID := firstNonEmpty(item.CVE, item.ID, firstCVE(item.Summary))
		if cveID == "" {
			continue
		}
		advisories = append(advisories, Advisory{
			CVEID:           cveID,
			Product:         product,
			AffectedVersion: firstNonEmpty(version, strings.Join(item.VulnerableConfiguration, " ")),
			CVSSv3Score:     item.CVSS,
			Description:     item.Summary,
			References:      compactStrings(item.References),
			Source:          c.name,
		})
	}
	return advisories, nil
}

func (c HTTPClient) searchVulners(ctx context.Context, product, version string) ([]Advisory, error) {
	payload := map[string]any{"query": product + " " + version + " type:cve"}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, nil
	}
	var parsed struct {
		Data struct {
			Search []struct {
				ID          string `json:"id"`
				Title       string `json:"title"`
				Description string `json:"description"`
				CVSS        struct {
					Score        float64 `json:"score"`
					VectorString string  `json:"vector"`
				} `json:"cvss"`
				Href           string   `json:"href"`
				References     []string `json:"references"`
				BulletinFamily string   `json:"bulletinFamily"`
			} `json:"search"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}
	var advisories []Advisory
	for _, item := range parsed.Data.Search {
		cveID := firstCVE(item.ID + " " + item.Title + " " + item.Description)
		if cveID == "" {
			continue
		}
		refs := append([]string{item.Href}, item.References...)
		advisories = append(advisories, Advisory{
			CVEID:            cveID,
			Product:          product,
			AffectedVersion:  version,
			CVSSv3Score:      item.CVSS.Score,
			CVSSv3Vector:     item.CVSS.VectorString,
			Description:      firstNonEmpty(item.Title, item.Description),
			ExploitAvailable: strings.EqualFold(item.BulletinFamily, "exploit"),
			References:       compactStrings(refs),
			Source:           c.name,
		})
	}
	return advisories, nil
}
