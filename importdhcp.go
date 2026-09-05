//go:build ignore

// One-shot importer: go run importdhcp.go sample.log
package main

import (
	"fmt"
	"os"

	"github.com/jaredwarren/Gofing/pkg/dhcp"
	"github.com/jaredwarren/Gofing/pkg/engine"
	"github.com/jaredwarren/Gofing/pkg/network"
	"github.com/jaredwarren/Gofing/pkg/store"
)

func main() {
	path := "sample.log"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	leases, err := dhcp.ParseFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse: %v\n", err)
		os.Exit(1)
	}

	db, err := store.Open(store.DefaultDBPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "open store: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	eng := engine.New(db)
	if info, err := network.GetActiveNetworkInfo(); err == nil {
		eng.SetActiveNetwork(info)
	}

	res := eng.ImportDHCPLeases(leases)
	fmt.Printf("DHCP import: %d updated, %d created, %d skipped, %d rows parsed\n",
		res.Updated, res.Created, res.Skipped, len(leases))
}
