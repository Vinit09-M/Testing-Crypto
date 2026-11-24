package ledger

import (
    "crypto"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
)

func SignBatch(key *rsa.PrivateKey, record []byte) ([]byte, error) {
    digest := sha256.Sum256(record)
    return rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest[:], nil)
}
