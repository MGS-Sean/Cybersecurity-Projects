// ©AngelaMos | 2026
// pixel_test.go

package pixel_test

import (
	"bytes"
	"image/gif"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators/pixel"
)

const (
	expectedLength = 43
	expectedWidth  = 1
	expectedHeight = 1
)

var (
	gif89aMagic = []byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61}
	gifTrailer  = byte(0x3b)
)

func TestTransparentGIF_Length(t *testing.T) {
	require.Len(t, pixel.TransparentGIF, expectedLength)
}

func TestTransparentGIF_MagicBytes(t *testing.T) {
	require.True(t,
		bytes.HasPrefix(pixel.TransparentGIF, gif89aMagic),
		"expected GIF89a magic prefix, got % x", pixel.TransparentGIF[:len(gif89aMagic)],
	)
	require.Equal(t, gifTrailer, pixel.TransparentGIF[len(pixel.TransparentGIF)-1],
		"expected trailing GIF terminator 0x3B")
}

func TestTransparentGIF_DecodesAsImageGIF(t *testing.T) {
	img, err := gif.Decode(bytes.NewReader(pixel.TransparentGIF))
	require.NoError(t, err)
	require.NotNil(t, img)

	bounds := img.Bounds()
	require.Equal(t, expectedWidth, bounds.Dx())
	require.Equal(t, expectedHeight, bounds.Dy())
}

func TestContentType_IsImageGIF(t *testing.T) {
	require.Equal(t, "image/gif", pixel.ContentType)
}
