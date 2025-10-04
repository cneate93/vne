package assets

import _ "embed"

//go:embed report_template.html
var ReportTemplate string

//go:embed oui.min.json
var OUIData []byte
