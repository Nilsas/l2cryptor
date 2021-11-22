package l2cryptor

import "math/big"

type RSAKey interface {
	N() *big.Int // Modulus
	E() *big.Int // Public exponent
	D() *big.Int // Private exponent
}

type rsaKey struct {
	n *big.Int
	e *big.Int
	d *big.Int
}

func (k *rsaKey) setN(n string) *rsaKey {
	k.n, _ = new(big.Int).SetString(n, 16)
	return k
}

func (k *rsaKey) setE(e string) *rsaKey {
	k.e, _ = new(big.Int).SetString(e, 16)
	return k
}

func (k *rsaKey) setD(d string) *rsaKey {
	k.d, _ = new(big.Int).SetString(d, 16)
	return k
}

func (k *rsaKey) N() *big.Int { return k.n }

func (k *rsaKey) E() *big.Int { return k.e }

func (k *rsaKey) D() *big.Int { return k.d }
