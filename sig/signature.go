package sig

import (
	"crypto/sha256"
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

type MessageData struct {
	Receiver      string
	Uid           string
	ExpiredTime   uint64
	ExpiredHeight uint64
}

func (d *MessageData) rawMessage() []byte {
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

func (d *MessageData) Hash() []byte {
	hash := sha256.Sum256(d.rawMessage())
	return hash[:]
}

func (d *MessageData) DoubleHash() []byte {
	first := d.Hash()
	second := sha256.Sum256(first)
	return second[:]
}

func (d *MessageData) Sign(privKey *btcec.PrivateKey) ([]byte, error) {
	hash := d.DoubleHash()
	signature := ecdsa.Sign(privKey, hash[:])
	return signature.Serialize(), nil
}

func (d *MessageData) Verify(pubKey *btcec.PublicKey, s []byte) (bool, error) {
	hash := d.DoubleHash()
	sig, err := ecdsa.ParseDERSignature(s)
	if err != nil {
		return false, err
	}
	return sig.Verify(hash[:], pubKey), nil
}
