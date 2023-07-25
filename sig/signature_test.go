package sig

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/assert"
)

func TestRawMessage(t *testing.T) {
	data := &MessageData{
		Receiver:      "receiver",
		Uid:           "uid",
		ExpiredTime:   123456,
		ExpiredHeight: 789,
	}

	raw := data.rawMessage()
	assert.Equal(t, "exph=789&expt=123456&rec=receiver&uid=uid", string(raw))

	data = &MessageData{
		Receiver:      "receiver",
		Uid:           "uid",
		ExpiredTime:   123456,
		ExpiredHeight: 0,
	}

	raw = data.rawMessage()
	assert.Equal(t, "expt=123456&rec=receiver&uid=uid", string(raw))
}

func TestSignAndVerify(t *testing.T) {
	privKey, err := btcec.NewPrivateKey()
	assert.NoError(t, err)

	pubKey := privKey.PubKey()

	// convert public key to compressed format in hex string
	pubKeyHex := hex.EncodeToString(pubKey.SerializeCompressed())

	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	assert.NoError(t, err)
	pubKey, err = btcec.ParsePubKey(pubKeyBytes)
	assert.NoError(t, err)

	data := &MessageData{
		Receiver:      "receiver",
		Uid:           "uid",
		ExpiredTime:   123456,
		ExpiredHeight: 789,
	}

	sig, err := data.Sign(privKey)
	assert.NoError(t, err)

	valid, err := data.Verify(pubKey, sig)
	assert.NoError(t, err)
	assert.True(t, valid)

	// Change one of the fields and verify that the signature is invalid
	data.Receiver = "new_receiver"
	valid, err = data.Verify(pubKey, sig)
	assert.NoError(t, err)
	assert.False(t, valid)
}
