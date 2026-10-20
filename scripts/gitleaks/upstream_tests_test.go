// Keep immutable detector test imports in the maintenance module graph.
// These imports run no upstream code here; build-gitleaks.sh runs its real tests.
package maintenance_test

import (
	_ "github.com/google/go-cmp/cmp"
	_ "github.com/lucasjones/reggen"
	_ "github.com/stretchr/testify/assert"
	_ "github.com/stretchr/testify/require"
	_ "github.com/wasilibs/go-re2"
)
