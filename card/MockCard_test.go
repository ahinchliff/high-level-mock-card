package card

import (
	"crypto/ecdsa"
	"crypto/rand"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
)

const (
	CURVE_TYPE uint32 = 1
)

var VALID_CA_PRIVATE_KEY, _ = ethcrypto.GenerateKey()
var INVALID_CA_PRIVATE_KEY, _ = ethcrypto.GenerateKey()
var VALID_ATTESTER_PRIVATE_KEY, _ = ethcrypto.GenerateKey()
var INVALID_ATTESTER_PRIVATE_KEY, _ = ethcrypto.GenerateKey()
var ISSUER_PRIVATE_KEY, _ = ethcrypto.GenerateKey()
var BRAND_ONE = randomBytes(32)
var BRAND_TWO = randomBytes(32)

func TestNewCard(t *testing.T) {
	assert := assert.New(t)

	validCard := newCardWithValidCertificate()
	invalidCard := newCardWithInvalidCertificate()

	assert.True(cardCertificateIsValid(validCard.Certificate, VALID_CA_PRIVATE_KEY.PublicKey), "Certificate should be valid")
	assert.False(cardCertificateIsValid(invalidCard.Certificate, VALID_CA_PRIVATE_KEY.PublicKey), "Certificate should be invalid")
}

func TestSendAndReceivePhonon(t *testing.T) {
	assert := assert.New(t)

	sender := newCardWithValidCertificate()
	recipient := newCardWithValidCertificate()
	senderPhononIndex := sender.CreatePhonon(CURVE_TYPE)

	sentPhonon, err := sender.GetPhonon(senderPhononIndex)
	assert.NoError(err)

	packet, err := sender.SendPhonon(senderPhononIndex, recipient.PublicKey, recipient.NextTransactionNonce(), false, 0)
	assert.NoError(err)
	assert.True(transferPacketContentsIsValid(packet), "Packet should be valid")

	recipientKeyIndex, err := recipient.ReceivePhonon(packet)
	assert.NoError(err)

	receivedPhonon, err := recipient.GetPhonon(recipientKeyIndex)
	assert.NoError(err)

	assert.True(sentPhonon.privateKey.Equal(&receivedPhonon.privateKey), "PKs should be the same")
	assert.Equal(receivedPhonon.CurveType, sentPhonon.CurveType, "Curve types should be the same")
}

func TestCanOnlySendPhononOnce(t *testing.T) {
	assert := assert.New(t)

	sender := newCardWithValidCertificate()
	recipient := newCardWithValidCertificate()
	phononIndex := sender.CreatePhonon(CURVE_TYPE)

	sender.SendPhonon(phononIndex, recipient.PublicKey, recipient.NextTransactionNonce(), false, 0)
	_, err := sender.SendPhonon(phononIndex, recipient.PublicKey, recipient.NextTransactionNonce(), false, 0)

	assert.Equal(err, ErrPhononNotFound)
}

func TestPhononCanOnlyBeReceivedOnce(t *testing.T) {
	assert := assert.New(t)

	sender := newCardWithValidCertificate()
	recipient := newCardWithValidCertificate()
	phononIndex := sender.CreatePhonon(CURVE_TYPE)

	packet, err := sender.SendPhonon(phononIndex, recipient.PublicKey, recipient.NextTransactionNonce(), false, 0)
	assert.NoError(err)

	recipient.ReceivePhonon(packet)
	_, err = recipient.ReceivePhonon(packet)

	assert.Equal(ErrInvalidNonce, err)
}

func TestPhononCantReceivePacketWithLowerNonce(t *testing.T) {
	assert := assert.New(t)

	sender := newCardWithValidCertificate()
	recipient := newCardWithValidCertificate()
	phononIndex1 := sender.CreatePhonon(CURVE_TYPE)
	phononIndex2 := sender.CreatePhonon(CURVE_TYPE)

	packet1, err := sender.SendPhonon(phononIndex1, recipient.PublicKey, recipient.NextTransactionNonce(), false, 0)
	assert.NoError(err)

	packet2, err := sender.SendPhonon(phononIndex2, recipient.PublicKey, recipient.NextTransactionNonce(), false, 0)
	assert.NoError(err)

	recipient.ReceivePhonon(packet2)
	_, err = recipient.ReceivePhonon(packet1)
	assert.Equal(ErrInvalidNonce, err)
}

func TestPhononCanOnlyComeFromValidCard(t *testing.T) {
	assert := assert.New(t)

	sender := newCardWithInvalidCertificate()
	recipient := newCardWithValidCertificate()
	phononIndex := sender.CreatePhonon(CURVE_TYPE)

	packet, err := sender.SendPhonon(phononIndex, recipient.PublicKey, recipient.NextTransactionNonce(), false, 0)
	assert.NoError(err)

	_, err = recipient.ReceivePhonon(packet)
	assert.Equal(ErrInvalidSenderCard, err)
}

func TestPhononCanOnlyBeConsumedByRecipient(t *testing.T) {
	assert := assert.New(t)

	sender := newCardWithValidCertificate()
	recipient := newCardWithValidCertificate()
	notRecipient := newCardWithValidCertificate()
	phononIndex := sender.CreatePhonon(CURVE_TYPE)

	packet, err := sender.SendPhonon(phononIndex, recipient.PublicKey, recipient.NextTransactionNonce(), false, 0)
	assert.NoError(err)

	_, err = notRecipient.ReceivePhonon(packet)
	assert.Equal(ErrNotIntendedRecipient, err)
}

func newCardWithValidCertificate() *Card {
	c := New()
	cert := createCertificate(c, VALID_CA_PRIVATE_KEY)
	c.InstallCACertificate(cert)
	return c
}

func newCardWithInvalidCertificate() *Card {
	c := New()
	cert := createCertificate(c, INVALID_CA_PRIVATE_KEY)
	c.InstallCACertificate(cert)
	return c
}

func createCertificate(c *Card, caPrivateKey *ecdsa.PrivateKey) Certificate {
	certificateSignatureData := ethcrypto.FromECDSAPub(&c.PublicKey)
	certificateSignature, _ := ecdsa.SignASN1(rand.Reader, caPrivateKey, certificateSignatureData)

	return Certificate{
		CardPublicKey: c.privateKey.PublicKey,
		Signature:     certificateSignature,
		CAPublicKey:   caPrivateKey.PublicKey,
	}
}
