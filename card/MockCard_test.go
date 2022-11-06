package card

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	CURVE_TYPE uint32 = 1
)

var VALID_CA_PRIVATE_KEY, _ = rsa.GenerateKey(rand.Reader, 2048)
var INVALID_CA_PRIVATE_KEY, _ = rsa.GenerateKey(rand.Reader, 2048)
var VALID_ATTESTER_PRIVATE_KEY, _ = rsa.GenerateKey(rand.Reader, 2048)
var INVALID_ATTESTER_PRIVATE_KEY, _ = rsa.GenerateKey(rand.Reader, 2048)

// DEFINITIONS

// "attestor" - a third party that both users trust

// "locked phonon" - a phonon that cant be sent or redeemed until unlocked by an attestor.
//  Optionally, a locked phonon can be sent to a single recipent.

func TestUserStoryHappyPath(t *testing.T) {
	// Happy Path
	// Alice and Bob have a single phonon and they want to exchange with eachother. They are both good actors.
	assert := assert.New(t)

	alice := newCardWithValidCertificate()
	alicesPhononIndex := alice.CreatePhonon(CURVE_TYPE)
	alicesPhonon, err := alice.GetPhonon(alicesPhononIndex)
	assert.NoError(err)

	bob := newCardWithValidCertificate()
	bobsPhononIndex := bob.CreatePhonon(CURVE_TYPE)
	bobsPhonon, err := bob.GetPhonon(alicesPhononIndex)
	assert.NoError(err)

	// 1. They exchange their card's public keys and their their phonon's public keys, agree on an attester and confirm that the others phonon has the asset they want to aquire.

	// 2. They produce a nonce that is unique for their trade. This can be anything but both parties want it to be unique so they can verify the other party's phonon is locked.
	alicePublicKeyBytes := x509.MarshalPKCS1PublicKey(&alice.PublicKey)
	bobPublicKeyBytes := x509.MarshalPKCS1PublicKey(&bob.PublicKey)

	now := time.Now()
	timeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(timeBytes, uint32(now.Unix()))

	nonceData := append(alicePublicKeyBytes, bobPublicKeyBytes...)
	nonceData = append(nonceData, timeBytes...)

	nonce := sha256.Sum256(nonceData)

	// 3. Alice locks her phonon. Her phonon can now only be sent to Bob unless unlocked by the attestor.
	aliceLockProof, err := alice.LockPhonon(alicesPhononIndex, nonce[:], VALID_ATTESTER_PRIVATE_KEY.PublicKey, &bob.PublicKey)
	assert.NoError(err)

	// 5. Alice sends her proof to Bob. Bob verifies the data and the proof. Bob is confident the phonon he wants is locked
	assert.Equal(aliceLockProof.PhononPublicKey, alicesPhonon.privateKey.PublicKey)
	assert.True(aliceLockProof.CounterpartyPublicKey.Equal(&bob.PublicKey))
	assert.Equal(aliceLockProof.Nonce, nonce[:])
	assert.True(phononLockProofIsValid(aliceLockProof))

	// 4. Bob locks his phonon
	bobLockProof, err := bob.LockPhonon(bobsPhononIndex, nonce[:], VALID_ATTESTER_PRIVATE_KEY.PublicKey, &alice.PublicKey)
	assert.NoError(err)

	// 5. Bob sends his proof to Alice. Alice verifies the data and the proof.
	assert.Equal(bobLockProof.PhononPublicKey, bobsPhonon.privateKey.PublicKey)
	assert.True(bobLockProof.CounterpartyPublicKey.Equal(&alice.PublicKey))
	assert.Equal(bobLockProof.Nonce, nonce[:])
	assert.True(phononLockProofIsValid(bobLockProof))

	// 6. Alice creates a transfer packet and sends it to Bob
	aliceTransferPacket, err := alice.SendPhonon(alicesPhononIndex, bob.PublicKey, bob.NextTransactionNonce(), false)
	assert.NoError(err)

	// 7. Bob creates a transfer packet and send it to Alice
	bobTransferPacket, err := bob.SendPhonon(bobsPhononIndex, alice.PublicKey, alice.NextTransactionNonce(), false)
	assert.NoError(err)

	// 8. Bob consumes the transfer packet. The phonon is locked on his card. He sends the unlock signature to alice
	bobsPhononIndex, bobProofReceived, err := bob.ReceivePhonon(aliceTransferPacket)
	assert.NoError(err)
	bobsPhonon, err = bob.GetPhonon(bobsPhononIndex)
	assert.NoError(err)
	assert.NotNil(bobsPhonon.Lock)

	// 9. Alice consumes the transfer packet. The phonon is locked on her card. She sends the unlock signature to bob.
	alicesPhononIndex, aliceProofReceived, err := alice.ReceivePhonon(bobTransferPacket)
	assert.NoError(err)
	alicesPhonon, err = alice.GetPhonon(alicesPhononIndex)
	assert.NoError(err)
	assert.NotNil(alicesPhonon.Lock)

	// 10. Bob unlocks his received phonon using the signature received from Alice
	err = bob.UnlockPhonon(bobsPhononIndex, false, aliceProofReceived)
	assert.NoError(err)
	assert.Nil(bobsPhonon.Lock)

	// 11. Alice unlocks her received phonon using the signature received from Bob
	err = alice.UnlockPhonon(alicesPhononIndex, false, bobProofReceived)
	assert.NoError(err)
	assert.Nil(alicesPhonon.Lock)
}

func TestBobNeverLocks(t *testing.T) {
	// Alice and Bob have a single phonon and they want to exchange with eachother. Bob is a knob.
	assert := assert.New(t)

	alice := newCardWithValidCertificate()
	alicesPhononIndex := alice.CreatePhonon(CURVE_TYPE)
	alicesPhonon, err := alice.GetPhonon(alicesPhononIndex)
	assert.NoError(err)

	bob := newCardWithValidCertificate()

	// 1. They exchange their card's public keys and their their phonon's public keys, agree on an attester and confirm that the others phonon has the asset they want to aquire.

	// 2. They produce a nonce that is unique for their trade. This can be anything but both parties want it to be unique so they can verify the other party's phonon is locked.
	alicePublicKeyBytes := x509.MarshalPKCS1PublicKey(&alice.PublicKey)
	bobPublicKeyBytes := x509.MarshalPKCS1PublicKey(&bob.PublicKey)

	now := time.Now()
	timeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(timeBytes, uint32(now.Unix()))

	nonceData := append(alicePublicKeyBytes, bobPublicKeyBytes...)
	nonceData = append(nonceData, timeBytes...)

	nonce := sha256.Sum256(nonceData)

	// 3. Alice locks her phonon. Her phonon can now only be sent to Bob unless unlocked by the attestor.
	aliceLockProof, err := alice.LockPhonon(alicesPhononIndex, nonce[:], VALID_ATTESTER_PRIVATE_KEY.PublicKey, &bob.PublicKey)
	assert.NoError(err)

	// 5. Alice sends her proof to Bob. Bob never responds. Alice sends her proof to the attester service.

	// 6. The service verifies her proof. They give Bob x amount of time to reply. The amount of time to wait can be included in the nonce.

	// 7. Bob never responds. The service creates an unlock signature for Alice
	unlockSignatureData := createUnlockPhononSignatureData(aliceLockProof.Nonce, alice.PublicKey)
	unlockSignatureSignature, err := rsa.SignPKCS1v15(rand.Reader, VALID_ATTESTER_PRIVATE_KEY, crypto.SHA256, unlockSignatureData)
	assert.NoError(err)

	// 8. Alice unlocks her phonon
	err = alice.UnlockPhonon(alicesPhononIndex, true, unlockSignatureSignature)
	assert.NoError(err)
	assert.Nil(alicesPhonon.Lock)
}

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

	recipientKeyIndex, _, err := recipient.ReceivePhonon(packet)
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
	senderPhononIndex := sender.CreatePhonon(CURVE_TYPE)

	sender.SendPhonon(senderPhononIndex, recipient.PublicKey, recipient.NextTransactionNonce(), false)
	_, err := sender.SendPhonon(senderPhononIndex, recipient.PublicKey, recipient.NextTransactionNonce(), false)

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
	_, _, err = recipient.ReceivePhonon(packet)

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
	_, _, err = recipient.ReceivePhonon(packet1)
	assert.Equal(err, ErrInvalidNonce)
}

func TestPhononCanOnlyComeFromValidCard(t *testing.T) {
	assert := assert.New(t)

	sender := newCardWithInvalidCertificate()
	recipient := newCardWithValidCertificate()
	phononIndex := sender.CreatePhonon(CURVE_TYPE)

	packet, err := sender.SendPhonon(phononIndex, recipient.PublicKey, recipient.NextTransactionNonce(), false)
	assert.NoError(err)

	_, _, err = recipient.ReceivePhonon(packet)
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

	_, _, err = notRecipient.ReceivePhonon(packet)
	assert.Equal(err, ErrNotIntendedRecipient)
}

func TestLockProofSignatureWithoutNonceOrCounterparty(t *testing.T) {
	assert := assert.New(t)

	sender := newCardWithValidCertificate()
	phononIndex := sender.CreatePhonon(CURVE_TYPE)
	proof, err := sender.LockPhonon(phononIndex, nil, VALID_ATTESTER_PRIVATE_KEY.PublicKey, nil)
	assert.NoError(err)

	assert.True(phononLockProofIsValid(proof))
}

func TestLockProofSignatureWithoutCounterparty(t *testing.T) {
	assert := assert.New(t)

	nonce := createNonce()

	sender := newCardWithValidCertificate()
	phononIndex := sender.CreatePhonon(CURVE_TYPE)
	proof, err := sender.LockPhonon(phononIndex, nonce, VALID_ATTESTER_PRIVATE_KEY.PublicKey, nil)
	assert.NoError(err)

	assert.True(phononLockProofIsValid(proof))
}

func TestLockProofSignature(t *testing.T) {
	assert := assert.New(t)

	recipient := newCardWithValidCertificate()

	nonce := createNonce()

	sender := newCardWithValidCertificate()
	phononIndex := sender.CreatePhonon(CURVE_TYPE)
	proof, err := sender.LockPhonon(phononIndex, nonce, VALID_ATTESTER_PRIVATE_KEY.PublicKey, &recipient.PublicKey)
	assert.NoError(err)

	assert.True(phononLockProofIsValid(proof))
}

func TestPreventRedeemWhenLocked(t *testing.T) {
	assert := assert.New(t)

	sender := newCardWithValidCertificate()
	phononIndex := sender.CreatePhonon(CURVE_TYPE)
	nonce := createNonce()

	_, err := sender.LockPhonon(phononIndex, nonce, VALID_ATTESTER_PRIVATE_KEY.PublicKey, nil)
	assert.NoError(err)

	_, err = sender.RedeemPhonon(phononIndex)

	assert.Equal(err, ErrPhononLocked)
}

func TestPreventSendToWrongRecipientWhenLocked(t *testing.T) {
	assert := assert.New(t)

	sender := newCardWithValidCertificate()
	recipient := newCardWithValidCertificate()
	wrongRecipient := newCardWithValidCertificate()
	phononIndex := sender.CreatePhonon(CURVE_TYPE)

	nonce := createNonce()

	_, err := sender.LockPhonon(phononIndex, nonce, VALID_ATTESTER_PRIVATE_KEY.PublicKey, &recipient.PublicKey)
	assert.NoError(err)

	_, err = sender.SendPhonon(phononIndex, wrongRecipient.PublicKey, recipient.NextTransactionNonce(), false)
	assert.Equal(err, ErrPhononLocked)
}

func TestSendAndReceiveWhenLocked(t *testing.T) {
	assert := assert.New(t)

	sender := newCardWithValidCertificate()
	recipient := newCardWithValidCertificate()
	phononIndex := sender.CreatePhonon(CURVE_TYPE)
	nonce := createNonce()

	_, err := sender.LockPhonon(phononIndex, nonce, VALID_ATTESTER_PRIVATE_KEY.PublicKey, &recipient.PublicKey)
	assert.NoError(err)

	packet, err := sender.SendPhonon(phononIndex, recipient.PublicKey, recipient.NextTransactionNonce(), false)
	assert.NoError(err)

	assert.True(transferPacketContentsIsValid(packet), "Packet should be valid")

	recipientIndex, _, err := recipient.ReceivePhonon(packet)
	assert.NoError(err)

	receivedPhonon, err := recipient.GetPhonon(recipientIndex)
	assert.NoError(err)

	assert.NotNil(receivedPhonon.Lock, "Phonon should be locked")
}

func TestUnlockPhononWithValidAttesterSignature(t *testing.T) {
	assert := assert.New(t)

	sender := newCardWithValidCertificate()
	phononIndex := sender.CreatePhonon(CURVE_TYPE)

	nonce := createNonce()
	_, err := sender.LockPhonon(phononIndex, nonce, VALID_ATTESTER_PRIVATE_KEY.PublicKey, nil)
	assert.NoError(err)

	phonon, err := sender.GetPhonon(phononIndex)
	assert.NoError(err)

	unlockSignatureData := createUnlockPhononSignatureData(phonon.Lock.Nonce, sender.PublicKey)

	unlockSignatureSignature, err := rsa.SignPKCS1v15(rand.Reader, VALID_ATTESTER_PRIVATE_KEY, crypto.SHA256, unlockSignatureData)
	assert.NoError(err)

	sender.UnlockPhonon(phononIndex, true, unlockSignatureSignature)

	assert.Nil(phonon.Lock, "Phonon should be unlocked")
}

func TestUnlockPhononWithValidRecipientSignature(t *testing.T) {
	assert := assert.New(t)
	alice := newCardWithValidCertificate()
	alicesPhononIndex := alice.CreatePhonon(CURVE_TYPE)

	bob := newCardWithValidCertificate()
	bobPhononIndex := bob.CreatePhonon(CURVE_TYPE)

	nonce := createNonce()

	_, err := alice.LockPhonon(alicesPhononIndex, nonce, VALID_ATTESTER_PRIVATE_KEY.PublicKey, &bob.PublicKey)
	assert.NoError(err)

	_, err = bob.LockPhonon(bobPhononIndex, nonce, VALID_ATTESTER_PRIVATE_KEY.PublicKey, &alice.PublicKey)
	assert.NoError(err)

	alicesPacket, err := alice.SendPhonon(alicesPhononIndex, bob.PublicKey, bob.NextTransactionNonce(), false)
	assert.NoError(err)

	bobsPacket, err := bob.SendPhonon(bobPhononIndex, alice.PublicKey, alice.NextTransactionNonce(), false)
	assert.NoError(err)

	bobPhononIndex, alicesUnlockSignature, err := bob.ReceivePhonon(alicesPacket)
	assert.NoError(err)

	alicesPhononIndex, bobsUnlockSignature, err := alice.ReceivePhonon(bobsPacket)
	assert.NoError(err)

	err = bob.UnlockPhonon(bobPhononIndex, false, bobsUnlockSignature)
	assert.NoError(err)

	err = alice.UnlockPhonon(alicesPhononIndex, false, alicesUnlockSignature)
	assert.NoError(err)

	bobsPhonon, err := bob.GetPhonon(bobPhononIndex)
	assert.NoError(err)
	assert.Nil(bobsPhonon.Lock)

	alicesPhonon, err := alice.GetPhonon(alicesPhononIndex)
	assert.NoError(err)
	assert.Nil(alicesPhonon.Lock)
}

func TestPreventsUnlockPhononWithInvalidAttesterSignature(t *testing.T) {
	assert := assert.New(t)

	sender := newCardWithValidCertificate()
	recipient := newCardWithValidCertificate()
	phononIndex := sender.CreatePhonon(CURVE_TYPE)
	nonce := createNonce()

	_, err := sender.LockPhonon(phononIndex, nonce, VALID_ATTESTER_PRIVATE_KEY.PublicKey, nil)
	assert.NoError(err)

	phonon, err := sender.GetPhonon(phononIndex)
	assert.NoError(err)

	wrongNonce := createNonce()

	// signature created with incorrect nonce
	unlockSignatureData1 := createUnlockPhononSignatureData(wrongNonce, sender.PublicKey)

	unlockSignatureSignature1, err := rsa.SignPKCS1v15(rand.Reader, VALID_ATTESTER_PRIVATE_KEY, crypto.SHA256, unlockSignatureData1)
	assert.NoError(err)

	sender.UnlockPhonon(phononIndex, true, unlockSignatureSignature1)
	assert.NotNil(phonon.Lock, "Phonon should be locked")

	// signature created for different card
	unlockSignatureData2 := createUnlockPhononSignatureData(phonon.Lock.Nonce, recipient.PublicKey)
	unlockSignatureSignature2, err := rsa.SignPKCS1v15(rand.Reader, VALID_ATTESTER_PRIVATE_KEY, crypto.SHA256, unlockSignatureData2)
	assert.NoError(err)

	sender.UnlockPhonon(phononIndex, true, unlockSignatureSignature2)
	assert.NotNil(phonon.Lock, "Phonon should be locked")
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

func createNonce() []byte {
	id := make([]byte, 32)
	rand.Read(id)
	return id
}
