/*
significant portions of this are adapted from
https://gist.github.com/eliquious/9e96017f47d9bd43cdf9
*/

package main

import (
	"bytes"
	"crypto"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

type raven_key struct {
	Email      string `json:"email"`
	PublicKey  string `json:"publickey"`
	PrivateKey string `json:"privatekey"`
}

func (keypair raven_key) String() string {
	j, _ := json.Marshal(keypair)
	return string(j)
}

type raven_keyring map[string]raven_key

func (keyring raven_keyring) String() string {
	res := ""
	for i, key := range keyring {
		line := fmt.Sprintf("key %v: %v\n", i, key)
		res += line
	}
	return res
}

func (keyring raven_keyring) Json() string {
	j, _ := json.Marshal(keyring)
	return string(j)
}

func genGPGKeys(email string) (keypair raven_key) {

	keypair = raven_key{
		Email: email,
	}

	entity, err := openpgp.NewEntity(email, "", email, nil)
	if err != nil {
		log.Fatalf("cannot create entity: %v\n", err)
	}

	{
		// public
		var buf bytes.Buffer
		armor_w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
		if err != nil {
			log.Fatalf("cannot add armor: %v\n", err)
		}
		if err = entity.Serialize(armor_w); err != nil {
			log.Fatalf("cannot serialize: %v\n", err)
		}
		armor_w.Close()
		keypair.PublicKey = string(buf.Bytes())
	}
	{
		// private
		var buf bytes.Buffer
		armor_w, err := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
		if err != nil {
			log.Fatalf("cannot add armor: %v\n", err)
		}
		if err = entity.SerializePrivate(armor_w, nil); err != nil {
			log.Fatalf("cannot serialize: %v\n", err)
		}
		armor_w.Close()
		keypair.PrivateKey = string(buf.Bytes())
	}

	return
}

func makeKeyRing(filename string, num int) {
	var keyring raven_keyring
	var email string
	keyring = make(raven_keyring, 0)
	for key_iterator := 0; key_iterator < num; key_iterator++ {
		email = fmt.Sprintf("race-server-%05d@racemail-raven.test", key_iterator)
		logDebug("generating key for ", email)
		keys := genGPGKeys(email)
		keyring[email] = keys
		email = fmt.Sprintf("race-client-%05d@racemail-raven.test", key_iterator)
		logDebug("generating key for ", email)
		keys = genGPGKeys(email)
		keyring[email] = keys
	}
	// create a dummy entry
	keys := genGPGKeys("dummy")
	keyring["dummy"] = keys
	// save to file
	f, err := os.Create(filename) // TODO: set appropriate umask
	defer f.Close()
	if err != nil {
		log.Panicf("cannot create file '%v'; err=%s\n", filename, err)
	}
	f.Write([]byte(keyring.Json()))
}

func loadKeyRing(filename string) raven_keyring {
	var f *os.File
	var err error
	if f, err = os.Open(filename); err != nil {
		log.Panicf("cannot open '%v': err=%v\n", filename, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		log.Panicf("cannot state file %v; err=%v\n", filename, err)
	}
	length := fi.Size()
	buf := make([]byte, length)
	if _, err = f.Read(buf); err != nil {
		log.Panicf("cannot read file: %v\n", err)
	}
	var keyring raven_keyring
	if err := json.Unmarshal(buf, &keyring); err != nil {
		log.Panicf("cannot unmarshal json: %v\n", err)
	}
	return keyring
}

func decodePublicKey(pubkey raven_key) *packet.PublicKey {

	in := bytes.NewBuffer([]byte(pubkey.PublicKey))
	block, err := armor.Decode(in)
	if err != nil {
		log.Fatalf("Error decoding OpenPGP Armor: %s", err)
	}
	if block.Type != openpgp.PublicKeyType {
		log.Fatalf("invalid public key")
	}

	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()

	key, ok := pkt.(*packet.PublicKey)
	if !ok {
		log.Fatalf("invalid public key")
	}
	return key
}

func decodePrivateKey(privkey raven_key) *packet.PrivateKey {

	in := bytes.NewBuffer([]byte(privkey.PrivateKey))
	block, err := armor.Decode(in)
	if err != nil {
		log.Fatalf("Error decoding OpenPGP Armor: %s", err)
	}

	if block.Type != openpgp.PrivateKeyType {
		log.Fatalf("invalid private key")
	}

	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()

	key, ok := pkt.(*packet.PrivateKey)
	if !ok {
		log.Fatalf("invalid private key")
	}
	return key
}

func createEntityFromKeys(pubKey *packet.PublicKey, privKey *packet.PrivateKey) *openpgp.Entity {
	config := packet.Config{
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionNone,
		RSABits:                2048,
	}
	currentTime := config.Now()
	uid := packet.NewUserId("", "", "")

	e := openpgp.Entity{
		PrimaryKey: pubKey,
		PrivateKey: privKey,
		Identities: make(map[string]*openpgp.Identity),
	}
	isPrimaryId := false

	e.Identities[uid.Id] = &openpgp.Identity{
		Name:   uid.Name,
		UserId: uid,
		SelfSignature: &packet.Signature{
			CreationTime: currentTime,
			SigType:      packet.SigTypePositiveCert,
			PubKeyAlgo:   packet.PubKeyAlgoRSA,
			Hash:         config.Hash(),
			IsPrimaryId:  &isPrimaryId,
			FlagsValid:   true,
			FlagSign:     true,
			FlagCertify:  true,
			IssuerKeyId:  &e.PrimaryKey.KeyId,
		},
	}

	keyLifetimeSecs := uint32(86400 * 365)

	e.Subkeys = make([]openpgp.Subkey, 1)
	e.Subkeys[0] = openpgp.Subkey{
		PublicKey:  pubKey,
		PrivateKey: privKey,
		Sig: &packet.Signature{
			CreationTime:              currentTime,
			SigType:                   packet.SigTypeSubkeyBinding,
			PubKeyAlgo:                packet.PubKeyAlgoRSA,
			Hash:                      config.Hash(),
			PreferredHash:             []uint8{8}, // SHA-256
			FlagsValid:                true,
			FlagEncryptStorage:        true,
			FlagEncryptCommunications: true,
			IssuerKeyId:               &e.PrimaryKey.KeyId,
			KeyLifetimeSecs:           &keyLifetimeSecs,
		},
	}
	return &e
}
