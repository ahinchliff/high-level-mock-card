package card

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/GridPlus/keycard-go/crypto"
	"github.com/ahinchliff/high-level-mock-card/card/assetType"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

var ErrInvalidInput = errors.New("invalid input")
var ErrPhononNotFound = errors.New("phonon not found")
var ErrCertficateAlreadyInstalled = errors.New("cert already installed")
var ErrNotIntendedRecipient = errors.New("not intended recipient")
var ErrInvalidSenderCard = errors.New("invalid sender card")
var ErrInvalidTransferPacketSignature = errors.New("invalid packet signature")
var ErrInvalidNonce = errors.New("invalid nonce")
var ErrCantModifyAssetType = errors.New("cant modify asset type")
var ErrInvalidAssetType = errors.New("invalid asset type")
var ErrPhononNotFlexible = errors.New("phonon not flexible")
var ErrDifferentBrands = errors.New("different brands")
var ErrInsufficientBalance = errors.New("different brands")
var ErrInvalidSignature = errors.New("invalid signature")
var ErrIncorrectPhonon = errors.New("incorrect phonon")
var ErrPhononFlexible = errors.New("phonon already flexible")

type Certificate struct {
	CardPublicKey ecdsa.PublicKey
	CAPublicKey   ecdsa.PublicKey
	Signature     []byte
}

type Phonon struct {
	KeyIndex   uint32
	AssetType  assetType.AssetType
	CurveType  uint32
	Brand      [32]byte
	Value      uint32
	privateKey ecdsa.PrivateKey
}

type Card struct {
	privateKey             ecdsa.PrivateKey
	PublicKey              ecdsa.PublicKey
	Certificate            *Certificate
	transactionNonce       uint32
	postedTransactionNonce uint32
	phonons                []*Phonon
	deletedPhononIndexes   []uint32
}

type PhononTransferPacket struct {
	IsPosted            bool
	RecipientsPublicKey ecdsa.PublicKey
	Nonce               uint32
	PhononPublicKey     ecdsa.PublicKey
	EncryptedPrivateKey []byte
	SendersCertificate  Certificate
	Signature           []byte
	CurveType           uint32
	BrandPublicKey      [32]byte
	AssetType           uint32
	Value               uint32
	IV                  []byte
}

func New() *Card {
	privateKey, _ := ethcrypto.GenerateKey()

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

func (c *Card) MakePhononFlexible(phononIndex uint32, issuerPublicKey ecdsa.PublicKey, brand []byte, phononPublicKey ecdsa.PublicKey, value uint32, signature []byte) (err error) {
	phonon, _, err := c.retreivePhonon(phononIndex)
	if err != nil {
		return err
	}

	if phonon.AssetType == assetType.Flexible {
		return ErrPhononFlexible
	}

	if phonon.privateKey.PublicKey != phononPublicKey {
		return ErrIncorrectPhonon
	}

	signatureData := createCreateFlexiblePhononSignatureData(brand, c.PublicKey, phononPublicKey, value)
	if !ecdsa.VerifyASN1(&issuerPublicKey, signatureData, signature) {
		return ErrInvalidSignature
	}

	issuerPublicKeyBytes := ethcrypto.FromECDSAPub(&issuerPublicKey)
	brandData := append(issuerPublicKeyBytes, brand...)

	phonon.AssetType = assetType.Flexible
	phonon.Brand = sha256.Sum256(brandData)
	phonon.Value = value

	return nil
}

// todo - make more generic so users can set custom values in phonon metadata but unable to set restricted properties
func (c *Card) SetPhononDescription(keyIndex uint32, newAssetType assetType.AssetType, newValue uint32) error {
	phonon, _, err := c.retreivePhonon(keyIndex)
	if err != nil {
		return err
	}

	if phonon.AssetType == assetType.Native || phonon.AssetType == assetType.Flexible {
		return ErrCantModifyAssetType
	}

	if newAssetType == assetType.Native || newAssetType == assetType.Flexible {
		return ErrInvalidAssetType
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

func (c *Card) RedeemPhonon(keyIndex uint32, data []byte) (pk ecdsa.PrivateKey, signature []byte, err error) {
	phonon, otherPhonons, err := c.retreivePhonon(keyIndex)
	if err != nil {
		return pk, signature, err
	}

	if phonon.AssetType == assetType.Flexible {
		signatureData := createRedeemFlexiblePhononSignatureData(phonon.Brand, &phonon.privateKey, phonon.Value, data)
		signature, err = ecdsa.SignASN1(rand.Reader, &c.privateKey, signatureData)

		if err != nil {
			return pk, signature, err
		}
	} else {
		pk = phonon.privateKey
	}

	c.deletedPhononIndexes = append(c.deletedPhononIndexes, phonon.KeyIndex)
	c.phonons = otherPhonons

	return pk, signature, nil
}

func (c *Card) SendPhonon(keyIndex uint32, recipientsPublicKey ecdsa.PublicKey, nonce uint32, isPosted bool, value uint32) (packet PhononTransferPacket, err error) {
	phonon, otherPhonons, err := c.retreivePhonon(keyIndex)
	if err != nil {
		return packet, err
	}

	if phonon.AssetType == assetType.Flexible && value > phonon.Value {
		return packet, ErrInsufficientBalance
	}

	if phonon.AssetType == assetType.Flexible {
		phonon.Value = phonon.Value - value
	}

	secret := crypto.GenerateECDHSharedSecret(&c.privateKey, &recipientsPublicKey)

	iv := randomBytes(16)

	// todo - add salt
	phononEncryptedPrivateKey, err := crypto.EncryptData(ethcrypto.FromECDSA(&phonon.privateKey), secret, iv)
	if err != nil {
		return packet, err
	}

	signatureData := createSendPhononSignatureData(isPosted, recipientsPublicKey, nonce, phonon.privateKey.PublicKey, phononEncryptedPrivateKey, phonon.AssetType, phonon.Value, phonon.Brand)
	signature, err := ecdsa.SignASN1(rand.Reader, &c.privateKey, signatureData)
	if err != nil {
		return packet, err
	}

	packet = PhononTransferPacket{
		IsPosted:            isPosted,
		RecipientsPublicKey: recipientsPublicKey,
		Nonce:               nonce,
		PhononPublicKey:     phonon.privateKey.PublicKey,
		EncryptedPrivateKey: phononEncryptedPrivateKey,
		SendersCertificate:  *c.Certificate,
		Signature:           signature,
		CurveType:           phonon.CurveType,
		AssetType:           phonon.AssetType,
		Value:               phonon.Value,
		BrandPublicKey:      phonon.Brand,
		IV:                  iv,
	}

	if phonon.AssetType != assetType.Flexible {
		c.deletedPhononIndexes = append(c.deletedPhononIndexes, phonon.KeyIndex)
		c.phonons = otherPhonons
	}

	return packet, err
}

func (c *Card) ReceivePhonon(packet PhononTransferPacket) (keyIndex uint32, err error) {
	if !packet.RecipientsPublicKey.Equal(&c.PublicKey) {
		return keyIndex, ErrNotIntendedRecipient
	}

	if !cardCertificateIsValid(&packet.SendersCertificate, c.Certificate.CAPublicKey) {
		return keyIndex, ErrInvalidSenderCard
	}

	if !transferPacketContentsIsValid(packet) {
		return keyIndex, ErrInvalidTransferPacketSignature
	}

	if packet.IsPosted && packet.Nonce <= c.postedTransactionNonce {
		return keyIndex, ErrInvalidNonce
	}

	if !packet.IsPosted && packet.Nonce <= c.transactionNonce {
		return keyIndex, ErrInvalidNonce
	}

	secret := crypto.GenerateECDHSharedSecret(&c.privateKey, &packet.SendersCertificate.CardPublicKey)

	phononPrivateKeyBytes, err := crypto.DecryptData(packet.EncryptedPrivateKey, secret, packet.IV)
	if err != nil {
		return keyIndex, err
	}

	phononPrivateKey, _ := ethcrypto.ToECDSA(phononPrivateKeyBytes)

	keyIndex = c.nextPhononKeyIndex()

	phonon := &Phonon{
		KeyIndex:   keyIndex,
		CurveType:  packet.CurveType,
		privateKey: *phononPrivateKey,
		Value:      packet.Value,
		Brand:      packet.BrandPublicKey,
	}

	c.phonons = append(c.phonons, phonon)

	if packet.IsPosted {
		c.postedTransactionNonce = packet.Nonce
	} else {
		c.transactionNonce = packet.Nonce
	}

	return keyIndex, nil
}

func (c *Card) GetPhonon(keyIndex uint32) (*Phonon, error) {
	phonon, _, err := c.retreivePhonon(keyIndex)
	return phonon, err
}

func (c *Card) MergeFlexiblePhonons(keyIndex1 uint32, keyIndex2 uint32) error {
	if keyIndex1 == keyIndex2 {
		return ErrInvalidInput
	}

	phonon1, _, err := c.retreivePhonon(keyIndex1)
	if err != nil {
		return err
	}

	phonon2, remainingPhonons, err := c.retreivePhonon(keyIndex2)
	if err != nil {
		return err
	}

	if phonon1.AssetType != assetType.Flexible || phonon2.AssetType != assetType.Flexible {
		return ErrPhononNotFlexible
	}

	if phonon1.Brand != phonon2.Brand {
		return ErrDifferentBrands
	}

	phonon1.Value = phonon1.Value + phonon2.Value

	c.deletedPhononIndexes = append(c.deletedPhononIndexes, phonon2.KeyIndex)
	c.phonons = remainingPhonons
	if err != nil {
		return err
	}

	return nil
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

func createSendPhononSignatureData(isPosted bool, recipientsPublicKey ecdsa.PublicKey, nonce uint32, phononPublicKey ecdsa.PublicKey, phononEncryptedPrivateKey []byte, at assetType.AssetType, value uint32, brand [32]byte) []byte {
	phononPublicKeyBytes := ethcrypto.FromECDSAPub(&phononPublicKey)
	recipientsPublicKeyBytes := ethcrypto.FromECDSAPub(&recipientsPublicKey)

	nonceBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(nonceBytes, nonce)

	assetTypeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(assetTypeBytes, at)

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
	sigData = append(sigData, brand[:]...)

	return sigData
}

func createCreateFlexiblePhononSignatureData(brand []byte, recipientsPublicKey ecdsa.PublicKey, phononPublicKey ecdsa.PublicKey, value uint32) []byte {
	recipientsPublicKeyBytes := ethcrypto.FromECDSAPub(&recipientsPublicKey)
	phononPublicKeyBytes := ethcrypto.FromECDSAPub(&phononPublicKey)

	valueBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(valueBytes, value)

	sigData := append(recipientsPublicKeyBytes, phononPublicKeyBytes...)
	sigData = append(sigData, brand...)
	sigData = append(sigData, valueBytes...)

	return sigData
}

func createRedeemFlexiblePhononSignatureData(brand [32]byte, phononPrivateKey *ecdsa.PrivateKey, value uint32, data []byte) []byte {
	phononPrivateKeyBytes := ethcrypto.FromECDSA(phononPrivateKey)

	valueBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(valueBytes, value)

	sigData := append(brand[:], phononPrivateKeyBytes...)
	sigData = append(sigData, valueBytes...)
	sigData = append(sigData, data...)

	return sigData
}

func transferPacketContentsIsValid(packet PhononTransferPacket) bool {
	signatureData := createSendPhononSignatureData(packet.IsPosted, packet.RecipientsPublicKey, packet.Nonce, packet.PhononPublicKey, packet.EncryptedPrivateKey, packet.AssetType, packet.Value, packet.BrandPublicKey)
	return ecdsa.VerifyASN1(&packet.SendersCertificate.CardPublicKey, signatureData, packet.Signature)
}

func cardCertificateIsValid(certificate *Certificate, caPublicKey ecdsa.PublicKey) bool {
	signatureData := ethcrypto.FromECDSAPub(&certificate.CardPublicKey)
	return ecdsa.VerifyASN1(&caPublicKey, signatureData[:], certificate.Signature)
}

func randomBytes(length uint32) []byte {
	key := make([]byte, length)
	rand.Read(key)
	return key
}
