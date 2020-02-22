//go:generate gomobile bind -target ios github.com/l-vitaly/pspklib github.com/sah4ez/pspk/pkg/pspk

package pspklib

import (
	"encoding/json"
	"errors"

	"github.com/sah4ez/pspk/pkg/keys"
	"github.com/sah4ez/pspk/pkg/pspk"
	"github.com/sah4ez/pspk/pkg/utils"
)

var hkdfInfo = []byte("pspk_info")

type Key interface {
	ID() string
	Name() string
	Key() string
}

type keyWrapper struct {
	k pspk.Key
}

func (k *keyWrapper) ID() string {
	return k.k.ID
}

func (k *keyWrapper) Name() string {
	return k.k.Name
}

func (k *keyWrapper) Key() string {
	return k.k.Key
}

type Keys struct {
	items []pspk.Key
}

func (a *Keys) Len() int {
	return len(a.items)
}

func (a *Keys) At(i int) Key {
	return &keyWrapper{k: a.items[i]}
}

func (a *Keys) UnmarshalJSON(b []byte) error {
	if err := json.Unmarshal(b, &a.items); err != nil {
		return err
	}
	return nil
}

func (a *Keys) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.items)
}

type GenerateDHResult struct {
	Priv []byte
	Pub  []byte
}

type Pspk struct {
	priv *[32]byte
	pub  *[32]byte
}

// NewPspk makes a new Pspk.
func NewPspk() *Pspk {
	return &Pspk{}
}

func (p *Pspk) GenerateDH() (*GenerateDHResult, error) {
	var err error
	p.pub, p.priv, err = keys.GenerateDH()
	if err != nil {
		return nil, err
	}
	return &GenerateDHResult{
		Priv: p.priv[:],
		Pub:  p.pub[:],
	}, nil
}

func (p *Pspk) SecretLatestKey() []byte {
	return keys.Secret(p.priv[:], p.pub[:])
}

func (p *Pspk) Secret(priv, pub []byte) ([]byte, error) {
	if len(priv) != 32 {
		return nil, errors.New("private key must be 32 bytes length")
	}
	if len(pub) != 32 {
		return nil, errors.New("public key must be 32 bytes length")
	}
	return keys.Secret(priv, pub), nil
}

func (p *Pspk) Sign(priv, message, random []byte) ([]byte, error) {
	if len(priv) != 32 {
		return nil, errors.New("private key must be 32 bytes length")
	}
	if len(random) != 64 {
		return nil, errors.New("random must be 32 bytes length")
	}
	var priv32 *[32]byte
	var random64 [64]byte
	copy(priv32[:], priv[:32])
	copy(random64[:], random[:64])
	return keys.Sign(priv32, message, random64)[:], nil
}

func (p *Pspk) HKDF(secret []byte, outputLen int) ([]byte, error) {
	out, err := keys.HKDF(secret, hkdfInfo, outputLen)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (p *Pspk) EphemeralEncrypt(pub, data []byte) ([]byte, error) {
	if len(pub) != 32 {
		return nil, errors.New("public key must be 32 bytes length")
	}
	pubEphemeral, privEphemeral, err := keys.GenerateDH()
	if err != nil {
		return nil, err
	}
	chain := keys.Secret(privEphemeral[:], pub)
	messageKey, err := keys.LoadMaterialKey(chain)
	if err != nil {
		return nil, err
	}
	b, err := utils.Encrypt(messageKey[64:], messageKey[:32], data)
	if err != nil {
		return nil, err
	}
	return append(pubEphemeral[:], b...), nil
}

func (p *Pspk) Encrypt(key, plaintext []byte) ([]byte, error) {
	out, err := utils.Encrypt(key[64:], key[:32], plaintext)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (p *Pspk) EphemeralDecrypt(priv, data []byte) ([]byte, error) {
	if len(priv) != 32 {
		return nil, errors.New("private key must be 32 bytes length")
	}
	if len(data) <= 32 {
		return nil, errors.New("data is not ephemeral encrypt")
	}

	chain := keys.Secret(priv, data[:32])
	dataKey, err := keys.LoadMaterialKey(chain)
	if err != nil {
		return nil, err
	}
	result, err := utils.Decrypt(dataKey[64:], dataKey[:32], data[32:])
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *Pspk) Decrypt(key, cipherText []byte) ([]byte, error) {
	out, err := utils.Decrypt(key[64:], key[:32], cipherText)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (p *Pspk) LoadMaterialKey(chain []byte) ([]byte, error) {
	out, err := keys.LoadMaterialKey(chain)
	if err != nil {
		return nil, err
	}
	return out, nil
}

type API struct {
	api pspk.PSPK
}

type GetAllOptions struct {
	NameKey   string
	NameRegex string
	Output    string
	LastKey   string
	Limit     int
}

func (a *API) GetAll(opts *GetAllOptions) (*Keys, error) {
	options := pspk.GetAllOptions{
		Output: "json-array",
		Limit:  10,
	}
	if opts != nil {
		options.LastKey = opts.LastKey
		options.NameKey = opts.NameKey
		options.NameRegex = opts.NameRegex
		options.Output = opts.Output
		options.Limit = opts.Limit
	}
	result, err := a.api.GetAll(options)
	if err != nil {
		return nil, err
	}
	return &Keys{items: result}, nil
}

func (a *API) Publish(name string, key []byte) error {
	return a.api.Publish(name, key)
}

func (a *API) Load(name string) ([]byte, error) {
	data, err := a.api.Load(name)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (a *API) GenerateLink(data string) (string, error) {
	link, err := a.api.GenerateLink(data)
	if err != nil {
		return "", err
	}
	return link, nil
}

func (a *API) DownloadByLink(link string) (string, error) {
	data, err := a.api.DownloadByLink(link)
	if err != nil {
		return "", err
	}
	return data, nil
}

func NewAPI(basePath string) *API {
	return &API{
		api: pspk.New(basePath),
	}
}
