//go:build tools

// Retain the external import graph of pinned detector source during dependency updates.
// Upstream source: 83d9cd684c87d95d656c1458ef04895a7f1cbd8e.
// Not copied to or compiled into the detector; implementation stays upstream.
package tools

import (
	_ "github.com/BobuSumisu/aho-corasick"
	_ "github.com/Masterminds/sprig/v3"
	_ "github.com/charmbracelet/lipgloss"
	_ "github.com/fatih/semgroup"
	_ "github.com/gitleaks/go-gitdiff/gitdiff"
	_ "github.com/google/go-cmp/cmp"
	_ "github.com/google/go-cmp/cmp/cmpopts"
	_ "github.com/h2non/filetype"
	_ "github.com/hashicorp/go-version"
	_ "github.com/lucasjones/reggen"
	_ "github.com/mholt/archives"
	_ "github.com/rs/zerolog"
	_ "github.com/rs/zerolog/log"
	_ "github.com/spf13/cobra"
	_ "github.com/spf13/viper"
	_ "github.com/stretchr/testify/assert"
	_ "github.com/stretchr/testify/require"
	_ "github.com/wasilibs/go-re2"
	_ "golang.org/x/exp/maps"
)
