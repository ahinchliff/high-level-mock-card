package card

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	CURVE_TYPE uint32 = 1
)

var VALID_CA_PRIVATE_KEY, _ = rsa.GenerateKey(rand.Reader, 2048)
var INVALID_CA_PRIVATE_KEY, _ = rsa.GenerateKey(rand.Reader, 2048)
var VALID_ATTESTER_PRIVATE_KEY, _ = rsa.GenerateKey(rand.Reader, 2048)
var INVALID_ATTESTER_PRIVATE_KEY, _ = rsa.GenerateKey(rand.Reader, 2048)

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

	packet, err := sender.SendPhonon(senderPhononIndex, recipient.PublicKey, recipient.NextTransactionNonce(), false)
	assert.NoError(err)
	assert.True(transferPacketContentsIsValid(packet), "Packet should be valid")

	recipientKeyIndex, err := recipient.ReceivePhonon(packet)
	assert.NoError(err)

	receivedPhonon, err := recipient.GetPhonon(recipientKeyIndex)
	assert.NoError(err)

	assert.True(sentPhonon.privateKey.Equal(&receivedPhonon.privateKey), "PKs should be the same")
	assert.Equal(sentPhonon.CurveType, receivedPhonon.CurveType, "Curve types should be the same")
}

func TestCanOnlySendPhononOnce(t *testing.T) {
	assert := assert.New(t)

	sender := newCardWithValidCertificate()
	recipient := newCardWithValidCertificate()
	phononIndex := sender.CreatePhonon(CURVE_TYPE)

	sender.SendPhonon(phononIndex, recipient.PublicKey, recipient.NextTransactionNonce(), false)
	_, err := sender.SendPhonon(phononIndex, recipient.PublicKey, recipient.NextTransactionNonce(), false)

	assert.Equal(err, ErrPhononNotFound)
}

func TestPhononCanOnlyBeReceivedOnce(t *testing.T) {
	assert := assert.New(t)

	sender := newCardWithValidCertificate()
	recipient := newCardWithValidCertificate()
	phononIndex := sender.CreatePhonon(CURVE_TYPE)

	packet, err := sender.SendPhonon(phononIndex, recipient.PublicKey, recipient.NextTransactionNonce(), false)
	assert.NoError(err)

	recipient.ReceivePhonon(packet)
	_, err = recipient.ReceivePhonon(packet)

	assert.Equal(err, ErrInvalidNonce)
}

func TestPhononCantReceivePacketWithLowerNonce(t *testing.T) {
	assert := assert.New(t)

	sender := newCardWithValidCertificate()
	recipient := newCardWithValidCertificate()
	phononIndex1 := sender.CreatePhonon(CURVE_TYPE)
	phononIndex2 := sender.CreatePhonon(CURVE_TYPE)

	packet1, err := sender.SendPhonon(phononIndex1, recipient.PublicKey, recipient.NextTransactionNonce(), false)
	assert.NoError(err)

	packet2, err := sender.SendPhonon(phononIndex2, recipient.PublicKey, recipient.NextTransactionNonce(), false)
	assert.NoError(err)

	recipient.ReceivePhonon(packet2)
	_, err = recipient.ReceivePhonon(packet1)
	assert.Equal(err, ErrInvalidNonce)
}

func TestPhononCanOnlyComeFromValidCard(t *testing.T) {
	assert := assert.New(t)

	sender := newCardWithInvalidCertificate()
	recipient := newCardWithValidCertificate()
	phononIndex := sender.CreatePhonon(CURVE_TYPE)

	packet, err := sender.SendPhonon(phononIndex, recipient.PublicKey, recipient.NextTransactionNonce(), false)
	assert.NoError(err)

	_, err = recipient.ReceivePhonon(packet)
	assert.Equal(err, ErrInvalidSenderCard)
}

func TestPhononCanOnlyBeConsumedByRecipient(t *testing.T) {
	assert := assert.New(t)

	sender := newCardWithValidCertificate()
	recipient := newCardWithValidCertificate()
	notRecipient := newCardWithValidCertificate()
	phononIndex := sender.CreatePhonon(CURVE_TYPE)

	packet, err := sender.SendPhonon(phononIndex, recipient.PublicKey, recipient.NextTransactionNonce(), false)
	assert.NoError(err)

	_, err = notRecipient.ReceivePhonon(packet)
	assert.Equal(err, ErrNotIntendedRecipient)
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

func createCertificate(c *Card, caPrivateKey *rsa.PrivateKey) Certificate {
	certificateSignatureData := sha256.Sum256(x509.MarshalPKCS1PublicKey(&c.PublicKey))
	certificateSignature, _ := rsa.SignPKCS1v15(rand.Reader, caPrivateKey, crypto.SHA256, certificateSignatureData[:])
	return Certificate{
		CardPublicKey: c.privateKey.PublicKey,
		Signature:     certificateSignature,
		CAPublicKey:   caPrivateKey.PublicKey,
	}
}
