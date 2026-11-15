package embargozerolog

import (
	"io"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/internal/output"
)

// NewWriter masks complete JSON events after zerolog encodes their fields.
// Both dependencies are required; nil dependencies panic.
// Close rejects incomplete events and seals the adapter without closing next.
// See the package documentation for framing and encoded-binary limits.
func NewWriter(next io.Writer, scanner *embargo.Scanner) io.WriteCloser {
	return output.NewWriter(next, scanner)
}
