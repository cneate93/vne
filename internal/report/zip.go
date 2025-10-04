package report

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"sort"
)

// WriteBundle creates a zip archive containing the rendered HTML report, a pretty
// printed JSON representation of the results, and any additional raw artifacts.
func WriteBundle(outZip string, results Results, raws map[string][]byte) error {
	if outZip == "" {
		return fmt.Errorf("outZip cannot be empty")
	}

	data, err := BundleBytes(results, raws)
	if err != nil {
		return err
	}
	return os.WriteFile(outZip, data, 0644)
}

// BundleBytes returns a zip archive containing the rendered HTML report, a
// pretty-printed JSON representation of the results, and any additional raw
// artifacts.
func BundleBytes(results Results, raws map[string][]byte) ([]byte, error) {
	htmlBytes, err := renderBundleHTML(results)
	if err != nil {
		return nil, fmt.Errorf("render html: %w", err)
	}

	jsonBytes, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal results: %w", err)
	}
	jsonBytes = append(jsonBytes, '\n')

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	if err := addZipFile(zw, "report.html", htmlBytes); err != nil {
		zw.Close()
		return nil, err
	}
	if err := addZipFile(zw, "summary.json", jsonBytes); err != nil {
		zw.Close()
		return nil, err
	}

	if len(raws) > 0 {
		keys := make([]string, 0, len(raws))
		for k := range raws {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, name := range keys {
			data := raws[name]
			if data == nil {
				data = []byte{}
			}
			if err := addZipFile(zw, name, data); err != nil {
				zw.Close()
				return nil, err
			}
		}
	}

	if err := zw.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func renderBundleHTML(results Results) ([]byte, error) {
	tplBytes, err := os.ReadFile("assets/report_template.html")
	if err != nil {
		tplBytes = []byte(defaultReportTemplate)
	}

	funcMap := template.FuncMap{
		"pct": func(v float64) string {
			return fmt.Sprintf("%.0f%%", v*100)
		},
		"ms1": func(v float64) string {
			return fmt.Sprintf("%.1f ms", v)
		},
	}

	tpl, err := template.New("rep").Funcs(funcMap).Parse(string(tplBytes))
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := tpl.Execute(&buf, results); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func addZipFile(zw *zip.Writer, name string, data []byte) error {
	writer, err := zw.Create(name)
	if err != nil {
		return err
	}
	if _, err := writer.Write(data); err != nil {
		return err
	}
	return nil
}
