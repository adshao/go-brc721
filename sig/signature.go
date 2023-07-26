package sig

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

type SigField string

const (
	SigFieldReceiver      SigField = "rec"
	SigFieldUid           SigField = "uid"
	SigFieldExpiredTime   SigField = "expt"
	SigFieldExpiredHeight SigField = "exph"
)

type DeploySig struct {
	PubKey string     `json:"pk"`
	Fields []SigField `json:"fields"`
}

type MintSig struct {
	Signature     string `json:"s"`
	Receiver      string `json:"rec"`
	Uid           string `json:"uid"`
	ExpiredTime   uint64 `json:"expt"`
	ExpiredHeight uint64 `json:"exph"`
}

func (d *MintSig) message() []byte {
	var keys []SigField
	if d.Receiver != "" {
		keys = append(keys, SigFieldReceiver)
	}
	if d.Uid != "" {
		keys = append(keys, SigFieldUid)
	}
	if d.ExpiredTime != 0 {
		keys = append(keys, SigFieldExpiredTime)
	}
	if d.ExpiredHeight != 0 {
		keys = append(keys, SigFieldExpiredHeight)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})
	var s []string
	for _, key := range keys {
		switch key {
		case SigFieldReceiver:
			s = append(s, fmt.Sprintf("%s=%s", key, d.Receiver))
		case SigFieldUid:
			s = append(s, fmt.Sprintf("%s=%s", key, d.Uid))
		case SigFieldExpiredTime:
			s = append(s, fmt.Sprintf("%s=%d", key, d.ExpiredTime))
		case SigFieldExpiredHeight:
			s = append(s, fmt.Sprintf("%s=%d", key, d.ExpiredHeight))
		}
	}
	return []byte(strings.Join(s, "&"))
}

func (d *MintSig) Hash() []byte {
	hash := sha256.Sum256(d.message())
	return hash[:]
}

func (d *MintSig) DoubleHash() []byte {
	first := d.Hash()
	second := sha256.Sum256(first)
	return second[:]
}

func (d *MintSig) Sign(privKey *btcec.PrivateKey) ([]byte, error) {
	hash := d.DoubleHash()
	signature := ecdsa.Sign(privKey, hash[:])
	return signature.Serialize(), nil
}

func (d *MintSig) Verify(pubKey *btcec.PublicKey) (bool, error) {
	hash := d.DoubleHash()
	sig, err := ecdsa.ParseDERSignature([]byte(d.Signature))
	if err != nil {
		return false, err
	}
	return sig.Verify(hash[:], pubKey), nil
}

func ParsePubKey(pubKeyHex string) (*btcec.PublicKey, error) {
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return nil, err
	}
	return btcec.ParsePubKey(pubKeyBytes)
}
