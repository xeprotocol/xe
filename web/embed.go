// Package web holds the embedded static assets for the xe web UI.
//
// The directory is the source AND the embedded artefact — there is no build
// step. Plain HTML + ES modules + CSS, served as-is by the UI handler in
// package api. Use --ui-dir on `xe node` to serve from disk during development.
package web

import "embed"

//go:embed *.html all:assets all:blocks all:accounts all:leases all:providers all:conflicts all:statechain all:wallet all:pending all:peers all:frontiers all:dao all:chat all:provider
var FS embed.FS
