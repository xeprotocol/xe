package metrics

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type dashboardJSON struct {
	UID        string      `json:"uid"`
	Title      string      `json:"title"`
	Templating templating  `json:"templating"`
	Panels     []panelJSON `json:"panels"`
}

type templating struct {
	List []templateVar `json:"list"`
}

type templateVar struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Query      string `json:"query"`
	Multi      bool   `json:"multi"`
	IncludeAll bool   `json:"includeAll"`
}

type panelJSON struct {
	ID      int          `json:"id"`
	Title   string       `json:"title"`
	Targets []targetJSON `json:"targets"`
}

type targetJSON struct {
	Expr string `json:"expr"`
}

func locateRepoFile(relPath string) (string, error) {
	candidates := []string{
		filepath.Join("..", relPath),
		relPath,
		filepath.Join(".", relPath),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", os.ErrNotExist
}

func loadDashboard(t *testing.T) dashboardJSON {
	t.Helper()
	path, err := locateRepoFile("deploy/monitoring/grafana/dashboards/xe-node-health.json")
	if err != nil {
		t.Fatalf("failed to locate xe-node-health.json: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}

	var d dashboardJSON
	if err := json.Unmarshal(data, &d); err != nil {
		t.Fatalf("failed to parse %s as JSON: %v", path, err)
	}
	return d
}

func TestDashboardNodeTemplating(t *testing.T) {
	d := loadDashboard(t)

	var nodeVar *templateVar
	for i := range d.Templating.List {
		if d.Templating.List[i].Name == "node" {
			nodeVar = &d.Templating.List[i]
			break
		}
	}

	if nodeVar == nil {
		t.Fatalf("template variable 'node' not found in dashboard")
	}

	if nodeVar.Type != "query" {
		t.Errorf("expected node variable type 'query', got %q", nodeVar.Type)
	}

	if !strings.Contains(nodeVar.Query, "label_values") || !strings.Contains(nodeVar.Query, "node") {
		t.Errorf("expected node query to query node labels, got %q", nodeVar.Query)
	}

	if !nodeVar.Multi {
		t.Errorf("expected node variable multi to be true")
	}

	if !nodeVar.IncludeAll {
		t.Errorf("expected node variable includeAll to be true")
	}
}

func TestDistinctFrontierFingerprintsPanel(t *testing.T) {
	d := loadDashboard(t)

	var panel13 *panelJSON
	for i := range d.Panels {
		if d.Panels[i].ID == 13 {
			panel13 = &d.Panels[i]
			break
		}
	}

	if panel13 == nil {
		t.Fatalf("panel 13 not found in dashboard")
	}

	if len(panel13.Targets) == 0 {
		t.Fatalf("panel 13 has no targets")
	}

	expr := panel13.Targets[0].Expr

	// Must not use the broken count by (xe_frontier_fingerprint) pattern which collapses to 1
	if strings.Contains(expr, "count by (xe_frontier_fingerprint)") {
		t.Errorf("panel 13 still contains broken 'count by (xe_frontier_fingerprint)': %s", expr)
	}

	// Must use count_values to properly group gauge values
	if !strings.Contains(expr, "count_values") {
		t.Errorf("panel 13 target must use count_values: %s", expr)
	}

	// Must wire up the $node template variable
	if !strings.Contains(expr, "$node") {
		t.Errorf("panel 13 target must reference $node: %s", expr)
	}

	expectedExpr := `count(count_values("fp", xe_frontier_fingerprint{node=~"$node"}))`
	if expr != expectedExpr {
		t.Errorf("expected panel 13 expr %q, got %q", expectedExpr, expr)
	}
}

func TestAllTargetsUseNodeSelector(t *testing.T) {
	d := loadDashboard(t)

	for _, p := range d.Panels {
		for i, tgt := range p.Targets {
			if tgt.Expr == "" {
				continue
			}
			if !strings.Contains(tgt.Expr, "$node") {
				t.Errorf("panel %d (%s) target %d expr does not reference $node: %s",
					p.ID, p.Title, i, tgt.Expr)
			}
		}
	}
}

func TestAlertRuleFrontierDivergence(t *testing.T) {
	path, err := locateRepoFile("deploy/monitoring/alerts.yml")
	if err != nil {
		t.Fatalf("failed to locate alerts.yml: %v", err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read alerts.yml: %v", err)
	}

	raw := string(content)
	if !strings.Contains(raw, "XEFrontierDivergence") {
		t.Errorf("expected alerts.yml to contain XEFrontierDivergence rule")
	}

	if !strings.Contains(raw, `count(count_values("fp", xe_frontier_fingerprint)) > 1`) {
		t.Errorf("expected alerts.yml to use count(count_values(\"fp\", xe_frontier_fingerprint)) > 1")
	}
}
