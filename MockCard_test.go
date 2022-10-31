package card

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"
)

const (
	CURVE_TYPE uint32 = 1
)

var VALID_CA_PRIVATE_KEY, _ = rsa.GenerateKey(rand.Reader, 2048)
var INVALID_CA_PRIVATE_KEY, _ = rsa.GenerateKey(rand.Reader, 2048)

func TestNewCard(t *testing.T) {
	validCard := newCardWithValidCertificate()
	invalidCard := newCardWithInvalidCertificate()

	if !cardCertificateIsValid(validCard.Certificate, VALID_CA_PRIVATE_KEY.PublicKey) {
		t.Errorf("Card's cert should be valid")
	}

	if cardCertificateIsValid(invalidCard.Certificate, VALID_CA_PRIVATE_KEY.PublicKey) {
		t.Errorf("Card's cert should not be valid")
	}
}

func TestPostPhonon(t *testing.T) {
	sender := newCardWithValidCertificate()
	recipient := newCardWithValidCertificate()
	phononIndex := sender.CreatePhonon(CURVE_TYPE)

	packet, _ := sender.PostPhonon(recipient.PublicKey, recipient.NextNonce(), phononIndex)

	if !postedPhononTransferPacketContentsIsValid(packet) {
		t.Errorf("Failed to verify packet")
	}
}

func TestCanOnlyPostPhononOnce(t *testing.T) {
	sender := newCardWithValidCertificate()
	recipient := newCardWithValidCertificate()
	phononIndex := sender.CreatePhonon(CURVE_TYPE)
	sender.PostPhonon(recipient.PublicKey, recipient.NextNonce(), phononIndex)
	_, err := sender.PostPhonon(recipient.PublicKey, recipient.NextNonce(), phononIndex)
	if err != ErrPhononNotFound {
		t.Errorf("Expected ErrPhononNotFound")
	}
}

func TestReceivePostedPhonon(t *testing.T) {
	sender := newCardWithValidCertificate()
	recipient := newCardWithValidCertificate()

	phononIndex := sender.CreatePhonon(CURVE_TYPE)
	sentPhonon := sender.Phonons[0]

	packet, _ := sender.PostPhonon(recipient.PublicKey, recipient.NextNonce(), phononIndex)
	err := recipient.ReceivePostedPhonon(packet)

	if err != nil {
		t.Errorf("Unexpected error")
	}

	receivedPhonon := recipient.Phonons[0]

	if !sentPhonon.privateKey.Equal(receivedPhonon.privateKey) {
		t.Errorf("Sent and received private keys dont match")
	}

	if sentPhonon.curveType != receivedPhonon.curveType {
		t.Errorf("Sent and received curve type dont match")
	}
}

func TestPostedPhononCanOnlyBeReceivedOnce(t *testing.T) {
	sender := newCardWithValidCertificate()
	recipient := newCardWithValidCertificate()
	phononIndex := sender.CreatePhonon(CURVE_TYPE)
	packet, _ := sender.PostPhonon(recipient.PublicKey, recipient.NextNonce(), phononIndex)
	recipient.ReceivePostedPhonon(packet)
	err := recipient.ReceivePostedPhonon(packet)
	if err != ErrInvalidNonce {
		t.Errorf("Expected ErrInvalidNonce")
	}
}

func TestPostedPhononCantConsumePacketWithLowerNonce(t *testing.T) {
	sender := newCardWithValidCertificate()
	recipient := newCardWithValidCertificate()
	phononIndex1 := sender.CreatePhonon(CURVE_TYPE)
	phononIndex2 := sender.CreatePhonon(CURVE_TYPE)
	packet1, _ := sender.PostPhonon(recipient.PublicKey, recipient.NextNonce(), phononIndex1)
	packet2, _ := sender.PostPhonon(recipient.PublicKey, recipient.NextNonce(), phononIndex2)

	recipient.ReceivePostedPhonon(packet2)
	err := recipient.ReceivePostedPhonon(packet1)

	if err != ErrInvalidNonce {
		t.Errorf("Expected ErrInvalidNonce")
	}
}

func TestPostedPhononCanOnlyComeFromValidCard(t *testing.T) {
	sender := newCardWithInvalidCertificate()
	recipient := newCardWithValidCertificate()
	phononIndex := sender.CreatePhonon(CURVE_TYPE)
	packet, _ := sender.PostPhonon(recipient.PublicKey, recipient.NextNonce(), phononIndex)

	err := recipient.ReceivePostedPhonon(packet)

	if err != ErrInvalidSenderCard {
		t.Errorf("Expected ErrInvalidSenderCard")
	}
}

func TestPostedPhononCanOnlyBeConsumedByRecipient(t *testing.T) {
	sender := newCardWithInvalidCertificate()
	recipient := newCardWithValidCertificate()
	notRecipeint := newCardWithValidCertificate()
	phononIndex := sender.CreatePhonon(CURVE_TYPE)
	packet, _ := sender.PostPhonon(recipient.PublicKey, recipient.NextNonce(), phononIndex)

	err := notRecipeint.ReceivePostedPhonon(packet)

	if err != ErrNotIntendedRecipient {
		t.Errorf("Expected ErrNotIntendedRecipient")
	}
}

func newCardWithValidCertificate() *MockCard {
	c := New()
	cert := createCertificate(c, VALID_CA_PRIVATE_KEY)
	c.InstallCACertificate(cert)
	return c
}

func newCardWithInvalidCertificate() *MockCard {
	c := New()
	cert := createCertificate(c, INVALID_CA_PRIVATE_KEY)
	c.InstallCACertificate(cert)
	return c
}

func createCertificate(c *MockCard, caPrivateKey *rsa.PrivateKey) MockCertificate {
	certificateSignatureData := sha256.Sum256(x509.MarshalPKCS1PublicKey(c.PublicKey))
	certificateSignature, _ := rsa.SignPKCS1v15(rand.Reader, caPrivateKey, crypto.SHA256, certificateSignatureData[:])
	return MockCertificate{
		CardPublicKey: &c.privateKey.PublicKey,
		Signature:     certificateSignature,
		CAPublicKey:   &caPrivateKey.PublicKey,
	}
}
