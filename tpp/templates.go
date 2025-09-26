package tpp

import (
	"fmt"
	"html/template"
	"log/slog"
	"net/http"

	"github.com/raidiam/recco-mock-tpp/shared/model"
)

// render renders an HTML template with the given data
func render(w http.ResponseWriter, name string, td *model.TemplateData) {
	var tmpl *template.Template

	newTemplate, err := buildTemplateFromDisk(name)
	if err != nil {
		slog.Error("error building template", "error", err.Error())
		http.Error(w, "Template not found", http.StatusNotFound)
		return
	}
	slog.Info("template built from disk", "name", name)
	tmpl = newTemplate

	if td == nil {
		td = &model.TemplateData{}
	}

	// Set Content-Type header for HTML templates
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if err := tmpl.ExecuteTemplate(w, name, td); err != nil {
		slog.Error("error executing template", "error", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// buildTemplateFromDisk loads a template from disk, trying multiple possible paths
func buildTemplateFromDisk(name string) (*template.Template, error) {
	possiblePaths := []string{
		fmt.Sprintf("./web/templates/%s", name),  // From repo root
		fmt.Sprintf("../web/templates/%s", name), // From tpp directory (when running tests)
	}

	var tmpl *template.Template
	var err error

	for _, path := range possiblePaths {
		tmpl, err = template.ParseFiles(path)
		if err == nil {
			return tmpl, nil
		}
	}

	return nil, fmt.Errorf("template %s not found in any of the expected locations: %v", name, possiblePaths)
}
