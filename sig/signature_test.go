package sig

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/assert"
)

func TestDeploySig(t *testing.T) {
	data := &DeploySig{
		PubKey: "0379f79637ec1cc5375c4e269e9d70eda426b5ecba5d4088234a89e8943dc4aa9f",
		Fields: []SigField{SigFieldReceiver, SigFieldUid, SigFieldExpiredTime, SigFieldExpiredHeight},
	}

	err := data.Validate()
	assert.NoError(t, err, "DeploySig should be valid")

	data = &DeploySig{
		PubKey: "0379f79637ec1cc5375c4e269e9d70eda426b5ecba5d4088234a89e8943dc4aa9f1",
		Fields: []SigField{SigFieldReceiver, SigFieldUid, SigFieldExpiredTime, SigFieldExpiredHeight},
	}
	err = data.Validate()
	assert.Error(t, err, "DeploySig should be invalid because of invalid public key")

	data = &DeploySig{
		PubKey: "0379f79637ec1cc5375c4e269e9d70eda426b5ecba5d4088234a89e8943dc4aa9f",
		Fields: []SigField{},
	}
	err = data.Validate()
	assert.Error(t, err, "DeploySig should be invalid because of empty fields")

	data = &DeploySig{
		PubKey: "0379f79637ec1cc5375c4e269e9d70eda426b5ecba5d4088234a89e8943dc4aa9f",
		Fields: []SigField{SigFieldReceiver, SigFieldUid, SigFieldExpiredTime, SigFieldExpiredHeight, "invalid"},
	}
	err = data.Validate()
	assert.Error(t, err, "DeploySig should be invalid because of invalid field")

	data = &DeploySig{
		PubKey: "0379f79637ec1cc5375c4e269e9d70eda426b5ecba5d4088234a89e8943dc4aa9f",
		Fields: []SigField{SigFieldReceiver, SigFieldUid, SigFieldExpiredTime, SigFieldExpiredHeight, SigFieldReceiver},
	}
	err = data.Validate()
	assert.Error(t, err, "DeploySig should be invalid because of duplicate field")
}

func TestRawMessage(t *testing.T) {
	data := &MintSig{
		Receiver:      "receiver",
		Uid:           "uid",
		ExpiredTime:   123456,
		ExpiredHeight: 789,
	}

	raw := data.message()
	assert.Equal(t, "exph=789&expt=123456&rec=receiver&uid=uid", string(raw))

	data = &MintSig{
		Receiver:      "receiver",
		Uid:           "uid",
		ExpiredTime:   123456,
		ExpiredHeight: 0,
	}

	raw = data.message()
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

	data := &MintSig{
		Receiver:      "receiver",
		Uid:           "uid",
		ExpiredTime:   123456,
		ExpiredHeight: 789,
	}

	sig, err := data.Sign(privKey)
	assert.NoError(t, err)

	data.Signature = string(sig)

	valid, err := data.Verify(pubKey)
	assert.NoError(t, err)
	assert.True(t, valid)

	// test Validate
	err = data.Validate(&DeploySig{
		PubKey: pubKeyHex,
		Fields: []SigField{SigFieldReceiver, SigFieldUid, SigFieldExpiredTime, SigFieldExpiredHeight},
	})
	assert.NoError(t, err)

	// Change one of the fields and verify that the signature is invalid
	data.Receiver = "new_receiver"
	valid, err = data.Verify(pubKey)
	assert.NoError(t, err)
	assert.False(t, valid)
}

func TestParsePubKey(t *testing.T) {
	privKey, err := btcec.NewPrivateKey()
	assert.NoError(t, err)

	pubKey := privKey.PubKey()
	// convert public key to compressed format in hex string
	pubKeyHex := hex.EncodeToString(pubKey.SerializeCompressed())

	pubKey, err = ParsePubKey(pubKeyHex)
	assert.NoError(t, err)
	assert.Equal(t, pubKeyHex, hex.EncodeToString(pubKey.SerializeCompressed()))
}

func TestValidateMintSig(t *testing.T) {
	mintSig := &MintSig{
		Receiver:      "",
		Uid:           "uid",
		ExpiredTime:   123456,
		ExpiredHeight: 789,
	}
	err := mintSig.Validate(&DeploySig{
		PubKey: "0379f79637ec1cc5375c4e269e9d70eda426b5ecba5d4088234a89e8943dc4aa9f",
		Fields: []SigField{SigFieldReceiver, SigFieldUid, SigFieldExpiredTime, SigFieldExpiredHeight},
	})
	// missing receiver
	assert.Error(t, err)

	mintSig = &MintSig{
		Receiver:      "receiver",
		Uid:           "",
		ExpiredTime:   123456,
		ExpiredHeight: 789,
	}
	err = mintSig.Validate(&DeploySig{
		PubKey: "0379f79637ec1cc5375c4e269e9d70eda426b5ecba5d4088234a89e8943dc4aa9f",
		Fields: []SigField{SigFieldReceiver, SigFieldUid, SigFieldExpiredTime, SigFieldExpiredHeight},
	})
	// missing uid
	assert.Error(t, err)

	mintSig = &MintSig{
		Receiver:      "receiver",
		Uid:           "uid",
		ExpiredTime:   0,
		ExpiredHeight: 789,
	}
	err = mintSig.Validate(&DeploySig{
		PubKey: "0379f79637ec1cc5375c4e269e9d70eda426b5ecba5d4088234a89e8943dc4aa9f",
		Fields: []SigField{SigFieldReceiver, SigFieldUid, SigFieldExpiredTime, SigFieldExpiredHeight},
	})
	// missing expired time
	assert.Error(t, err)

	mintSig = &MintSig{
		Receiver:      "receiver",
		Uid:           "uid",
		ExpiredTime:   123456,
		ExpiredHeight: 0,
	}
	err = mintSig.Validate(&DeploySig{
		PubKey: "0379f79637ec1cc5375c4e269e9d70eda426b5ecba5d4088234a89e8943dc4aa9f",
		Fields: []SigField{SigFieldReceiver, SigFieldUid, SigFieldExpiredTime, SigFieldExpiredHeight},
	})
	// missing expired height
	assert.Error(t, err)
}
