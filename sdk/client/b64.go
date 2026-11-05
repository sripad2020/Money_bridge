package client

import "encoding/base64"

func encodeB64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
