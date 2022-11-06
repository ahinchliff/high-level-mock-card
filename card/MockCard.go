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
var ErrPhononLocked = errors.New("phonon locked")
var ErrPhononNotLocked = errors.New("phonon not locked")
var ErrInvalidUnlockSignature = errors.New("invalid unlock signature")

type Certificate struct {
	CardPublicKey rsa.PublicKey
	CAPublicKey   rsa.PublicKey
	Signature     []byte
}

type PhononLock struct {
	Nonce                 []byte
	CounterpartyPublicKey *rsa.PublicKey
	AttesterPublicKey     rsa.PublicKey
}

type PhononLockProof struct {
	Nonce                 []byte
	PhononPublicKey       ecdsa.PublicKey
	CounterpartyPublicKey *rsa.PublicKey
	AttesterPublicKey     rsa.PublicKey
	Signature             []byte
	CardCertificate       Certificate
}

type Phonon struct {
	KeyIndex       uint32
	AssetType      uint32
	CurveType      uint32
	BrandPublicKey rsa.PublicKey
	Value          uint32
	privateKey     ecdsa.PrivateKey
	Lock       *PhononLock
}

type Card struct {
	privateKey             rsa.PrivateKey
	PublicKey              rsa.PublicKey
	Certificate            *Certificate
	transactionNonce       uint32
	postedTransactionNonce uint32
	phonons                []*Phonon
	deletedPhononIndexes   []uint32
}

type PhononTransferPacket struct {
	IsPosted            bool
	RecipientsPublicKey rsa.PublicKey
	Nonce               uint32
	PhononPublicKey     ecdsa.PublicKey
	EncryptedPrivateKey []byte
	SendersCertificate  Certificate
	Signature           []byte
	CurveType           uint32
	AssetType           uint32
	Value               uint32
	Lock                *PhononLock
}

func New() *Card {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	mockCard := &Card{
		privateKey:             *privateKey,
		PublicKey:              privateKey.PublicKey,
		transactionNonce:       0,
		postedTransactionNonce: 0,
		deletedPhononIndexes:   []uint32{},
	}

	return mockCard
}

func (c *Card) InstallCACertificate(certificate Certificate) error {
	if c.Certificate != nil {
		return ErrCertficateAlreadyInstalled
	}
	c.Certificate = &certificate
	return nil
}

func (c *Card) CreatePhonon(curveType uint32) (index uint32) {
	privateKey, _ := ethcrypto.GenerateKey()
	keyIndex := c.nextPhononKeyIndex()

	phonon := Phonon{
		KeyIndex:   keyIndex,
		CurveType:  curveType,
		privateKey: *privateKey,
	}

	c.phonons = append(c.phonons, &phonon)

	return keyIndex
}

func (c *Card) SetPhononDescription(keyIndex uint32, newAssetType uint32, newValue uint32) error {
	phonon, _, err := c.retreivePhonon(keyIndex)
	if err != nil {
		return err
	}

	phonon.AssetType = newAssetType
	phonon.Value = newValue

	return nil
}

func (c *Card) NextTransactionNonce() uint32 {
	return c.transactionNonce + 1
}

func (c *Card) NextPostedTransactionNonce() uint32 {
	return c.postedTransactionNonce + 1
}

func (c *Card) RedeemPhonon(keyIndex uint32) (pk ecdsa.PrivateKey, err error) {
	phonon, otherPhonons, err := c.retreivePhonon(keyIndex)
	if err != nil {
		return pk, err
	}

	if phonon.Lock != nil {
		return pk, ErrPhononLocked
	}

	c.deletedPhononIndexes = append(c.deletedPhononIndexes, phonon.KeyIndex)
	c.phonons = otherPhonons

	return phonon.privateKey, nil
}

func (c *Card) SendPhonon(keyIndex uint32, recipientsPublicKey rsa.PublicKey, nonce uint32, isPosted bool) (packet PhononTransferPacket, err error) {
	phonon, otherPhonons, err := c.retreivePhonon(keyIndex)
	if err != nil {
		return packet, err
	}

	if phonon.Lock != nil && (phonon.Lock.CounterpartyPublicKey == nil || !phonon.Lock.CounterpartyPublicKey.Equal(&recipientsPublicKey)) {
		return packet, ErrPhononLocked
	}

	phononEncryptedPrivateKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &recipientsPublicKey, ethcrypto.FromECDSA(&phonon.privateKey), []byte{})
	if err != nil {
		return packet, err
	}

	signatureData := createSendPhononSignatureData(isPosted, recipientsPublicKey, nonce, phonon.privateKey.PublicKey, phononEncryptedPrivateKey, phonon.AssetType, phonon.Value, phonon.Lock)
	signature, err := rsa.SignPKCS1v15(rand.Reader, &c.privateKey, crypto.SHA256, signatureData)

	packet = PhononTransferPacket{
		IsPosted:            isPosted,
		RecipientsPublicKey: recipientsPublicKey,
		Nonce:               nonce,
		PhononPublicKey:     phonon.privateKey.PublicKey,
		EncryptedPrivateKey: phononEncryptedPrivateKey,
		SendersCertificate:  *c.Certificate,
		Signature:           signature,
		CurveType:           phonon.CurveType,
	}

	if phonon.Lock != nil {
		packet.Lock = &PhononLock{
			Nonce:                 phonon.Lock.Nonce,
			AttesterPublicKey:     phonon.Lock.AttesterPublicKey,
			CounterpartyPublicKey: &c.PublicKey,
		}
	}

	c.deletedPhononIndexes = append(c.deletedPhononIndexes, phonon.KeyIndex)
	c.phonons = otherPhonons

	return packet, err
}

func (c *Card) ReceivePhonon(packet PhononTransferPacket) (keyIndex uint32, counterpartyUnlockSignature []byte, err error) {
	if !packet.RecipientsPublicKey.Equal(&c.PublicKey) {
		return keyIndex, counterpartyUnlockSignature, ErrNotIntendedRecipient
	}

	if !cardCertificateIsValid(&packet.SendersCertificate, c.Certificate.CAPublicKey) {
		return keyIndex, counterpartyUnlockSignature, ErrInvalidSenderCard
	}

	if !transferPacketContentsIsValid(packet) {
		return keyIndex, counterpartyUnlockSignature, ErrInvalidTransferPacketSignature
	}

	if packet.IsPosted && packet.Nonce <= c.postedTransactionNonce {
		return keyIndex, counterpartyUnlockSignature, ErrInvalidNonce
	}

	if !packet.IsPosted && packet.Nonce <= c.transactionNonce {
		return keyIndex, counterpartyUnlockSignature, ErrInvalidNonce
	}

	phononPrivateKeyBytes, _ := rsa.DecryptOAEP(sha256.New(), rand.Reader, &c.privateKey, packet.EncryptedPrivateKey, []byte{})

	phononPrivateKey, _ := ethcrypto.ToECDSA(phononPrivateKeyBytes)

	keyIndex = c.nextPhononKeyIndex()

	phonon := &Phonon{
		KeyIndex:   keyIndex,
		CurveType:  packet.CurveType,
		privateKey: *phononPrivateKey,
	}

	if packet.Lock != nil {
		counterpartyUnlockSignature, err = rsa.SignPKCS1v15(rand.Reader, &c.privateKey, crypto.SHA256, packet.Lock.Nonce)
		if err != nil {
			return keyIndex, nil, err
		}
		phonon.Lock = packet.Lock
	}

	c.phonons = append(c.phonons, phonon)

	if packet.IsPosted {
		c.postedTransactionNonce = packet.Nonce
	} else {
		c.transactionNonce = packet.Nonce
	}

	return keyIndex, counterpartyUnlockSignature, nil
}

func (c *Card) LockPhonon(keyIndex uint32, nonce []byte, attesterPublicKey rsa.PublicKey, recipientsPublicKey *rsa.PublicKey) (proof PhononLockProof, err error) {
	phonon, _, err := c.retreivePhonon(keyIndex)
	if err != nil {
		return proof, err
	}

	if phonon.Lock != nil {
		return proof, ErrPhononLocked
	}

	phonon.Lock = &PhononLock{
		Nonce:                 nonce,
		CounterpartyPublicKey: recipientsPublicKey,
		AttesterPublicKey:     attesterPublicKey,
	}

	signatureData := createPhononLockProofSignatureData(phonon.Lock.Nonce, phonon.privateKey.PublicKey, attesterPublicKey, recipientsPublicKey)
	signature, err := rsa.SignPKCS1v15(rand.Reader, &c.privateKey, crypto.SHA256, signatureData)
	if err != nil {
		return proof, err
	}

	proof = PhononLockProof{
		PhononPublicKey:       phonon.privateKey.PublicKey,
		Nonce:                 phonon.Lock.Nonce,
		CounterpartyPublicKey: recipientsPublicKey,
		AttesterPublicKey:     attesterPublicKey,
		Signature:             signature,
		CardCertificate:       *c.Certificate,
	}

	return proof, nil
}

func (c *Card) UnlockPhonon(keyIndex uint32, isAttesterSignature bool, signature []byte) error {
	phonon, _, err := c.retreivePhonon(keyIndex)
	if err != nil {
		return err
	}

	if phonon.Lock == nil {
		return ErrPhononNotLocked
	}

	if isAttesterSignature {
		unlockSignatureData := createUnlockPhononSignatureData(phonon.Lock.Nonce, c.PublicKey)
		signatureIsValid := rsa.VerifyPKCS1v15(&phonon.Lock.AttesterPublicKey, crypto.SHA256, unlockSignatureData, signature) == nil
		if !signatureIsValid {
			return ErrInvalidUnlockSignature
		}
	} else {
		signatureIsValid := rsa.VerifyPKCS1v15(phonon.Lock.CounterpartyPublicKey, crypto.SHA256, phonon.Lock.Nonce, signature) == nil
		if !signatureIsValid {
			return ErrInvalidUnlockSignature
		}
	}

	phonon.Lock = nil

	return nil
}

func (c *Card) GetPhonon(keyIndex uint32) (*Phonon, error) {
	phonon, _, err := c.retreivePhonon(keyIndex)
	return phonon, err
}

func (c *Card) retreivePhonon(keyIndex uint32) (phonon *Phonon, otherPhonons []*Phonon, err error) {

	for _, p := range c.phonons {
		if p.KeyIndex == keyIndex {
			phonon = p
		} else {
			otherPhonons = append(otherPhonons, p)
		}
	}

	if phonon == nil {
		err = ErrPhononNotFound
	}

	return phonon, otherPhonons, err
}

func (c *Card) nextPhononKeyIndex() (keyIndex uint32) {
	if len(c.deletedPhononIndexes) > 0 {
		keyIndex = c.deletedPhononIndexes[0]
		c.deletedPhononIndexes = c.deletedPhononIndexes[1:]
	} else {
		keyIndex = uint32(len(c.phonons))
	}

	return keyIndex
}

func createSendPhononSignatureData(isPosted bool, recipientsPublicKey rsa.PublicKey, nonce uint32, phononPublicKey ecdsa.PublicKey, phononEncryptedPrivateKey []byte, assetType uint32, value uint32, lock *PhononLock) []byte {
	phononPublicKeyBytes := ethcrypto.FromECDSAPub(&phononPublicKey)
	recipientsPublicKeyBytes := x509.MarshalPKCS1PublicKey(&recipientsPublicKey)

	nonceBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(nonceBytes, nonce)

	assetTypeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(assetTypeBytes, assetType)

	valueBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(valueBytes, value)

	isPostedBytes := make([]byte, 1)
	if isPosted {
		isPostedBytes[0] = 1
	} else {
		isPostedBytes[0] = 0
	}

	sigData := append(isPostedBytes, recipientsPublicKeyBytes...)
	sigData = append(sigData, nonceBytes...)
	sigData = append(sigData, phononPublicKeyBytes...)
	sigData = append(sigData, phononEncryptedPrivateKey...)
	sigData = append(sigData, phononEncryptedPrivateKey...)
	sigData = append(sigData, assetTypeBytes...)
	sigData = append(sigData, valueBytes...)

	if lock != nil {
		sigData = append(sigData, lock.Nonce...)
		attestersPublicKeyBytes := x509.MarshalPKCS1PublicKey(&lock.AttesterPublicKey)
		sigData = append(sigData, attestersPublicKeyBytes...)
	}

	hash := sha256.Sum256(sigData)

	return hash[:]
}

func createPhononLockProofSignatureData(
	nonce []byte,
	phononPublicKey ecdsa.PublicKey,
	attesterPublicKey rsa.PublicKey,
	counterpartyPublicKey *rsa.PublicKey,
) []byte {
	phononPublicKeyBytes := ethcrypto.FromECDSAPub(&phononPublicKey)
	attesterPublicKeyBytes := x509.MarshalPKCS1PublicKey(&attesterPublicKey)

	sigData := append(phononPublicKeyBytes, nonce...)
	sigData = append(sigData, attesterPublicKeyBytes...)

	if counterpartyPublicKey != nil {
		counterpartyPublicKeyBytes := x509.MarshalPKCS1PublicKey(counterpartyPublicKey)
		sigData = append(sigData, counterpartyPublicKeyBytes...)
	}

	hash := sha256.Sum256(sigData)
	return hash[:]
}

func createUnlockPhononSignatureData(nonce []byte, cardPublicKey rsa.PublicKey) []byte {
	recipientsPublicKeyBytes := x509.MarshalPKCS1PublicKey(&cardPublicKey)

	sigData := append(nonce, recipientsPublicKeyBytes...)

	hash := sha256.Sum256(sigData)
	return hash[:]
}

func transferPacketContentsIsValid(packet PhononTransferPacket) bool {
	signatureData := createSendPhononSignatureData(packet.IsPosted, packet.RecipientsPublicKey, packet.Nonce, packet.PhononPublicKey, packet.EncryptedPrivateKey, packet.AssetType, packet.Value, packet.Lock)
	return rsa.VerifyPKCS1v15(&packet.SendersCertificate.CardPublicKey, crypto.SHA256, signatureData, packet.Signature) == nil
}

func cardCertificateIsValid(certificate *Certificate, caPublicKey rsa.PublicKey) bool {
	signatureData := sha256.Sum256(x509.MarshalPKCS1PublicKey(&certificate.CardPublicKey))
	return rsa.VerifyPKCS1v15(&caPublicKey, crypto.SHA256, signatureData[:], certificate.Signature) == nil
}

func phononLockProofIsValid(proof PhononLockProof) bool {
	data := createPhononLockProofSignatureData(proof.Nonce, proof.PhononPublicKey, proof.AttesterPublicKey, proof.CounterpartyPublicKey)
	return rsa.VerifyPKCS1v15(&proof.CardCertificate.CardPublicKey, crypto.SHA256, data, proof.Signature) == nil
}
