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

func TestMergeFlexiblePhonons(t *testing.T) {
	VALUE_1 := uint32(100)
	VALUE_2 := uint32(200)

	assert := assert.New(t)
	sender := newCardWithValidCertificate()

	phononIndex1 := sender.CreatePhonon(CURVE_TYPE)
	phononIndex2 := sender.CreatePhonon(CURVE_TYPE)

	phonon1, err := sender.GetPhonon(phononIndex1)
	assert.NoError(err)
	phonon2, err := sender.GetPhonon(phononIndex2)
	assert.NoError(err)

	sig1, err := createFlexiblePhononSignature(ISSUER_PRIVATE_KEY, BRAND_ONE, &sender.PublicKey, &phonon1.privateKey.PublicKey, VALUE_1)
	assert.NoError(err)
	sig2, err := createFlexiblePhononSignature(ISSUER_PRIVATE_KEY, BRAND_ONE, &sender.PublicKey, &phonon2.privateKey.PublicKey, VALUE_2)
	assert.NoError(err)

	err = sender.MakePhononFlexible(phononIndex1, ISSUER_PRIVATE_KEY.PublicKey, BRAND_ONE, phonon1.privateKey.PublicKey, VALUE_1, sig1)
	assert.NoError(err)
	err = sender.MakePhononFlexible(phononIndex2, ISSUER_PRIVATE_KEY.PublicKey, BRAND_ONE, phonon2.privateKey.PublicKey, VALUE_2, sig2)
	assert.NoError(err)

	err = sender.MergeFlexiblePhonons(phononIndex1, phononIndex2)
	assert.NoError(err)

	phonon1, err = sender.GetPhonon(phononIndex1)
	assert.NoError(err)
	assert.Equal(VALUE_1+VALUE_2, phonon1.Value, "Expect phonons value equal value1 + value2")

	_, err = sender.GetPhonon(phononIndex2)
	assert.Equal(ErrPhononNotFound, err)
}

func TestPreventMergingDifferentBrandedFlexiblePhonons(t *testing.T) {
	assert := assert.New(t)

	sender := newCardWithValidCertificate()

	phononIndex1 := sender.CreatePhonon(CURVE_TYPE)
	phononIndex2 := sender.CreatePhonon(CURVE_TYPE)

	phonon1, err := sender.GetPhonon(phononIndex1)
	assert.NoError(err)
	phonon2, err := sender.GetPhonon(phononIndex2)
	assert.NoError(err)

	sig1, err := createFlexiblePhononSignature(ISSUER_PRIVATE_KEY, BRAND_ONE, &sender.PublicKey, &phonon1.privateKey.PublicKey, 100)
	assert.NoError(err)

	sig2, err := createFlexiblePhononSignature(ISSUER_PRIVATE_KEY, BRAND_TWO, &sender.PublicKey, &phonon2.privateKey.PublicKey, 100)
	assert.NoError(err)

	err = sender.MakePhononFlexible(phononIndex1, ISSUER_PRIVATE_KEY.PublicKey, BRAND_ONE, phonon1.privateKey.PublicKey, 100, sig1)
	assert.NoError(err)

	err = sender.MakePhononFlexible(phononIndex2, ISSUER_PRIVATE_KEY.PublicKey, BRAND_TWO, phonon2.privateKey.PublicKey, 100, sig2)
	assert.NoError(err)

	err = sender.MergeFlexiblePhonons(phononIndex1, phononIndex2)
	assert.Equal(ErrDifferentBrands, err)
}

func TestPreventMergingFlexiblePhononsIfNotFlexible(t *testing.T) {
	assert := assert.New(t)

	sender := newCardWithValidCertificate()

	phononIndex1 := sender.CreatePhonon(CURVE_TYPE)
	phononIndex2 := sender.CreatePhonon(CURVE_TYPE)

	phonon1, err := sender.GetPhonon(phononIndex1)
	assert.NoError(err)

	sig, err := createFlexiblePhononSignature(ISSUER_PRIVATE_KEY, BRAND_ONE, &sender.PublicKey, &phonon1.privateKey.PublicKey, 100)
	assert.NoError(err)

	err = sender.MakePhononFlexible(phononIndex1, ISSUER_PRIVATE_KEY.PublicKey, BRAND_ONE, phonon1.privateKey.PublicKey, 100, sig)
	assert.NoError(err)

	err = sender.MergeFlexiblePhonons(phononIndex1, phononIndex2)
	assert.Equal(ErrPhononNotFlexible, err)
}

func TestFlexiblePhononFlow(t *testing.T) {
	STARTING_BALANCE := uint32(100)
	SENDING_VALUE := uint32(50)

	assert := assert.New(t)

	sender := newCardWithValidCertificate()
	recipient := newCardWithValidCertificate()

	senderPhononIndex := sender.CreatePhonon(CURVE_TYPE)
	senderPhonon, err := sender.GetPhonon(senderPhononIndex)
	assert.NoError(err)

	sig, err := createFlexiblePhononSignature(ISSUER_PRIVATE_KEY, BRAND_ONE, &sender.PublicKey, &senderPhonon.privateKey.PublicKey, STARTING_BALANCE)
	assert.NoError(err)

	err = sender.MakePhononFlexible(senderPhononIndex, ISSUER_PRIVATE_KEY.PublicKey, BRAND_ONE, senderPhonon.privateKey.PublicKey, STARTING_BALANCE, sig)
	assert.NoError(err)

	packet, err := sender.SendPhonon(senderPhononIndex, recipient.PublicKey, recipient.NextTransactionNonce(), false, SENDING_VALUE)
	assert.NoError(err)

	recipientPhononIndex, err := recipient.ReceivePhonon(packet)
	assert.NoError(err)

	assert.Equal(STARTING_BALANCE-SENDING_VALUE, senderPhonon.Value)

	recipientPhonon, err := recipient.GetPhonon(recipientPhononIndex)
	assert.NoError(err)
	assert.Equal(SENDING_VALUE, recipientPhonon.Value)
	assert.Equal(senderPhonon.privateKey, recipientPhonon.privateKey)
	assert.Equal(senderPhonon.Brand, recipientPhonon.Brand)
}

func TestUserCanSplitFlexiblePhononBySendingToSelf(t *testing.T) {
	STARTING_BALANCE := uint32(100)
	SENDING_VALUE := uint32(50)

	assert := assert.New(t)

	sender := newCardWithValidCertificate()

	senderPhononIndex1 := sender.CreatePhonon(CURVE_TYPE)
	senderPhonon1, err := sender.GetPhonon(senderPhononIndex1)
	assert.NoError(err)

	sig, err := createFlexiblePhononSignature(ISSUER_PRIVATE_KEY, BRAND_ONE, &sender.PublicKey, &senderPhonon1.privateKey.PublicKey, STARTING_BALANCE)
	assert.NoError(err)

	err = sender.MakePhononFlexible(senderPhononIndex1, ISSUER_PRIVATE_KEY.PublicKey, BRAND_ONE, senderPhonon1.privateKey.PublicKey, STARTING_BALANCE, sig)
	assert.NoError(err)

	packet, err := sender.SendPhonon(senderPhononIndex1, sender.PublicKey, sender.NextTransactionNonce(), false, SENDING_VALUE)
	assert.NoError(err)

	senderPhononIndex2, err := sender.ReceivePhonon(packet)
	assert.NoError(err)

	assert.Equal(STARTING_BALANCE-SENDING_VALUE, senderPhonon1.Value)

	senderPhonon2, err := sender.GetPhonon(senderPhononIndex2)
	assert.NoError(err)
	assert.Equal(SENDING_VALUE, senderPhonon2.Value)
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

func createFlexiblePhononSignature(issuerPrivateKey *ecdsa.PrivateKey, brand []byte, recipentPublicKey *ecdsa.PublicKey, phononPublicKey *ecdsa.PublicKey, value uint32) ([]byte, error) {
	signatureData := createCreateFlexiblePhononSignatureData(brand, *recipentPublicKey, *phononPublicKey, value)
	return ecdsa.SignASN1(rand.Reader, issuerPrivateKey, signatureData)
}
