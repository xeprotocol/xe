package web

import "embed"

//go:embed *.html all:assets all:blocks all:accounts all:leases all:providers all:conflicts all:statechain all:wallet all:pending all:peers all:frontiers all:dao all:chat all:provider
var FS embed.FS
