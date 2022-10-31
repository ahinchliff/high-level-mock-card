package card

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

var ErrPhononNotFound = errors.New("phonon not found")
var ErrCertficateAlreadyInstalled = errors.New("cert already installed")
var ErrNotIntendedRecipient = errors.New("not intended recipient")
var ErrInvalidSenderCard = errors.New("invalid sender card")
var ErrInvalidTransferPacketSignature = errors.New("invalid packet signature")
var ErrInvalidNonce = errors.New("invalid nonce")

type MockCertificate struct {
	CardPublicKey *rsa.PublicKey
	CAPublicKey   *rsa.PublicKey
	Signature     []byte
}

type MockPhonon struct {
	KeyIndex   uint32
	curveType  uint32
	privateKey *ecdsa.PrivateKey
}

type MockCard struct {
	privateKey           *rsa.PrivateKey
	PublicKey            *rsa.PublicKey
	Certificate          *MockCertificate
	nonce                uint32
	Phonons              []*MockPhonon
	deletedPhononIndexes []uint32
}

type PostedPhononTransferPacket struct {
	RecipientsPublicKey *rsa.PublicKey
	Nonce               uint32
	PhononPublicKey     *ecdsa.PublicKey
	EncryptedPrivateKey []byte
	SendersCertificate  *MockCertificate
	Signature           []byte
	CurveType           uint32
}

func New() *MockCard {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	mockCard := &MockCard{
		privateKey:           privateKey,
		PublicKey:            &privateKey.PublicKey,
		nonce:                0,
		deletedPhononIndexes: []uint32{},
	}

	return mockCard
}

func (c *MockCard) InstallCACertificate(certificate MockCertificate) error {
	if c.Certificate != nil {
		return ErrCertficateAlreadyInstalled
	}
	c.Certificate = &certificate
	return nil
}

func (c *MockCard) CreatePhonon(curveType uint32) (index uint32) {
	privateKey, _ := ethcrypto.GenerateKey()
	keyIndex := c.nextPhononKeyIndex()

	phonon := MockPhonon{
		KeyIndex:   keyIndex,
		curveType:  curveType,
		privateKey: privateKey,
	}

	c.Phonons = append(c.Phonons, &phonon)

	return keyIndex
}

func (c *MockCard) NextNonce() uint32 {
	return c.nonce + 1
}

func (c *MockCard) RedeemPhonon(keyIndex uint32) (*ecdsa.PrivateKey, error) {
	var phonon *MockPhonon
	phonons := []*MockPhonon{}

	for _, p := range c.Phonons {
		if p.KeyIndex == keyIndex {
			phonon = p
		} else {
			phonons = append(phonons, p)
		}
	}

	if phonon == nil {
		return nil, ErrPhononNotFound
	}

	c.deletedPhononIndexes = append(c.deletedPhononIndexes, phonon.KeyIndex)
	c.Phonons = phonons

	return phonon.privateKey, nil
}

func (c *MockCard) PostPhonon(recipientsPublicKey *rsa.PublicKey, nonce uint32, keyIndex uint32) (packet PostedPhononTransferPacket, err error) {
	var phonon *MockPhonon
	phonons := []*MockPhonon{}

	for _, p := range c.Phonons {
		if p.KeyIndex == keyIndex {
			phonon = p
		} else {
			phonons = append(phonons, p)
		}
	}

	if phonon == nil {
		return packet, ErrPhononNotFound
	}

	phononEncryptedPrivateKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, recipientsPublicKey, ethcrypto.FromECDSA(phonon.privateKey), []byte{})
	if err != nil {
		return packet, err
	}

	signatureData := createPostedPhononSignatureData(recipientsPublicKey, nonce, &phonon.privateKey.PublicKey, phononEncryptedPrivateKey)

	signature, err := rsa.SignPKCS1v15(rand.Reader, c.privateKey, crypto.SHA256, signatureData)

	packet = PostedPhononTransferPacket{
		RecipientsPublicKey: recipientsPublicKey,
		Nonce:               nonce,
		PhononPublicKey:     &phonon.privateKey.PublicKey,
		EncryptedPrivateKey: phononEncryptedPrivateKey,
		SendersCertificate:  c.Certificate,
		Signature:           signature,
		CurveType:           phonon.curveType,
	}

	c.deletedPhononIndexes = append(c.deletedPhononIndexes, phonon.KeyIndex)
	c.Phonons = phonons

	return packet, err
}

func (c *MockCard) ReceivePostedPhonon(packet PostedPhononTransferPacket) error {
	if !packet.RecipientsPublicKey.Equal(c.PublicKey) {
		return ErrNotIntendedRecipient
	}

	if !cardCertificateIsValid(packet.SendersCertificate, *c.Certificate.CAPublicKey) {
		return ErrInvalidSenderCard
	}

	if !postedPhononTransferPacketContentsIsValid(packet) {
		return ErrInvalidTransferPacketSignature
	}

	if packet.Nonce <= c.nonce {
		return ErrInvalidNonce
	}

	phononPrivateKeyBytes, _ := rsa.DecryptOAEP(sha256.New(), rand.Reader, c.privateKey, packet.EncryptedPrivateKey, []byte{})

	phononPrivateKey, _ := ethcrypto.ToECDSA(phononPrivateKeyBytes)

	keyIndex := c.nextPhononKeyIndex()

	phonon := &MockPhonon{
		KeyIndex:   keyIndex,
		curveType:  packet.CurveType,
		privateKey: phononPrivateKey,
	}

	c.Phonons = append(c.Phonons, phonon)

	c.nonce = packet.Nonce

	return nil
}

func (c *MockCard) nextPhononKeyIndex() (keyIndex uint32) {
	if len(c.deletedPhononIndexes) > 0 {
		keyIndex = c.deletedPhononIndexes[0]
	} else {
		keyIndex = uint32(len(c.Phonons))
	}

	return keyIndex
}

func createPostedPhononSignatureData(recipientsPublicKey *rsa.PublicKey, nonce uint32, phononPublicKey *ecdsa.PublicKey, phononEncryptedPrivateKey []byte) []byte {
	recipientsPublicKeyBytes := x509.MarshalPKCS1PublicKey(recipientsPublicKey)
	phononPublicKeyBytes := ethcrypto.FromECDSAPub(phononPublicKey)

	nonceBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(nonceBytes, nonce)

	sig := append(recipientsPublicKeyBytes, nonceBytes...)
	sig = append(sig, phononPublicKeyBytes...)
	sig = append(sig, phononEncryptedPrivateKey...)
	hash := sha256.Sum256(sig)
	return hash[:]
}

func postedPhononTransferPacketContentsIsValid(packet PostedPhononTransferPacket) bool {
	signatureData := createPostedPhononSignatureData(packet.RecipientsPublicKey, packet.Nonce, packet.PhononPublicKey, packet.EncryptedPrivateKey)
	return rsa.VerifyPKCS1v15(packet.SendersCertificate.CardPublicKey, crypto.SHA256, signatureData, packet.Signature) == nil
}

func cardCertificateIsValid(certificate *MockCertificate, caPublicKey rsa.PublicKey) bool {
	signatureData := sha256.Sum256(x509.MarshalPKCS1PublicKey(certificate.CardPublicKey))
	return rsa.VerifyPKCS1v15(&caPublicKey, crypto.SHA256, signatureData[:], certificate.Signature) == nil
}
