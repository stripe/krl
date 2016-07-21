package krl

import (
	"bytes"
	"reflect"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestBasicRoundTrip(t *testing.T) {
	t.Parallel()

	krl1 := &KRL{GeneratedDate: 1136239445}
	buf, err := krl1.Marshal(rng("seed"), cakey)
	if err != nil {
		t.Fatal(err)
	}
	krl2, err := ParseKRL(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(krl1, krl2) {
		t.Fatalf("expected %v, got %v", krl1, krl2)
	}
}

func TestKRL1(t *testing.T) {
	t.Parallel()

	krl, err := ParseKRL(krlbuf1)
	if err != nil {
		t.Fatal(err)
	}

	if !krl.IsRevoked(key1cert1) {
		t.Errorf("key1cert1 should be revoked")
	}
	if !krl.IsRevoked(key1cert2) {
		t.Errorf("key1cert2 should be revoked")
	}
	if krl.IsRevoked(key2cert1) {
		t.Errorf("key2cert1 should not be revoked")
	}
	if !krl.IsRevoked(key2cert2) {
		t.Errorf("key2cert2 should be revoked")
	}

	out, err := krl.Marshal(rng("seed1"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(krlbuf1, out) {
		t.Fatalf("expected %x, got %x", krlbuf1, out)
	}
}

func TestKRL2(t *testing.T) {
	t.Parallel()

	krl, err := ParseKRL(krlbuf2)
	if err != nil {
		t.Fatal(err)
	}

	if !krl.IsRevoked(key1cert1) {
		t.Errorf("key1cert1 should be revoked")
	}
	if !krl.IsRevoked(key1cert2) {
		t.Errorf("key1cert2 should be revoked")
	}
	if !krl.IsRevoked(key2cert1) {
		t.Errorf("key2cert1 should be revoked")
	}
	if krl.IsRevoked(key2cert2) {
		t.Errorf("key2cert2 should not be revoked")
	}

	out, err := krl.Marshal(rng("seed2"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(krlbuf2, out) {
		t.Fatalf("expected %x, got %x", krlbuf2, out)
	}
}

func TestKRL3(t *testing.T) {
	t.Parallel()

	krl, err := ParseKRL(krlbuf3)
	if err != nil {
		t.Fatal(err)
	}

	if krl.IsRevoked(key1cert1) {
		t.Errorf("key1cert1 should not be revoked")
	}
	if krl.IsRevoked(key1cert2) {
		t.Errorf("key1cert2 should not be revoked")
	}
	if !krl.IsRevoked(key2cert1) {
		t.Errorf("key2cert1 should be revoked")
	}
	if !krl.IsRevoked(key2cert2) {
		t.Errorf("key2cert2 should be revoked")
	}

	out, err := krl.Marshal(rng("seed3"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(krlbuf3, out) {
		t.Fatalf("expected %x, got %x", krlbuf3, out)
	}
}

func TestSignatures(t *testing.T) {
	t.Parallel()

	krl := &KRL{
		GeneratedDate: 1136239445,
		Sections: []KRLSection{
			&KRLCertificateSection{
				CA: cakey.PublicKey(),
				Sections: []KRLCertificateSubsection{
					&KRLCertificateSerialList{9298},
				},
			},
		},
	}
	buf, err := krl.Marshal(rng("sig"), cakey, key1, key2)
	if err != nil {
		t.Fatal(err)
	}

	expected := MustDecode64(`U1NIS1JMCgAAAAABAAAAAEO5o1UAAAAAQ7mjVQAAAAAAAAAAAAAAAAAAAAABAAAArAAAAJcAAAAHc3NoLXJzYQAAAAMBAAEAAACBAKooUHhyxYmMyVQZ1RP0KktwX6CiEsXIaE1SA3XYjFyw0pzttXLLqbB0deluNjUR57D7WF7po8xY20EavDzW58JtfQQqLOhCvXr0BSJ5hoC58aVP21mKgKFwFTmVyOPmPUEa9dQ2/fK5Z1wuS7PMI1oD5/GVU4aqUhG6kZ7PtBN3AAAAACAAAAAIAAAAAAAAJFIEAAAAlwAAAAdzc2gtcnNhAAAAAwEAAQAAAIEAqihQeHLFiYzJVBnVE/QqS3BfoKISxchoTVIDddiMXLDSnO21csupsHR16W42NRHnsPtYXumjzFjbQRq8PNbnwm19BCos6EK9evQFInmGgLnxpU/bWYqAoXAVOZXI4+Y9QRr11Db98rlnXC5Ls8wjWgPn8ZVThqpSEbqRns+0E3cAAACPAAAAB3NzaC1yc2EAAACAHz4COpfmBvkAhb8JwRvJesHvWuKog40pTBgvTVIBw8ntMNUMfwEKPzt6r7AdS0Gzt6/DN2ljiEHBkdZmG+mVsxDbbUuQ9CkaimnQedlb1uloeulrS+WBVKE/VmgEOc5BZRcOIZFo2wren0YjtnTcT/mUmDiLg0RijZZivjtMdcAEAAAAlwAAAAdzc2gtcnNhAAAAAwEAAQAAAIEAp2YKkx9TuyFA4UkhiGTEkPQOK+0iputZcSxuPEA+GK46eVWFVUSCijb6gmb/+fF8N2ZsDlSUhG4PmQrQ/CCGIFewDmilJDN62LAxqn+sqxWgPghaFgWCOSa65N/Pdj8IcAr0JZ6pCmKabshTi7P4KiB1wALodMfoa53aGYagIE0AAACPAAAAB3NzaC1yc2EAAACABso0nidmDBn5P+3pKaGZixEJFiLKCKXrjaol/abJveTk5JUdLpLAeqfl7Tu+k8KaO33G5rovOYgjxv6O03B4KH5hkYsUXl/ZGyoa0fNkMw9QTwCj/9znWrghXnHrDNeY+MfoaV8N+P4kqx8AxS+MvNHXaUcMCUSJQ0TXmvbVx0oEAAAAlwAAAAdzc2gtcnNhAAAAAwEAAQAAAIEA1vxBrEF1zOyvXoHKybN5LYFHCpqYjEEphp9B5EqE6Zb6xmwvy9U+XMGRLbCpTdDv2ipOGQ91TqwjfaTrJBagnKYzs11SBfO+cq4T4HJEimDeXPWbDK2DX8dPxtwlMpqf4lJvS/s0qFluV8yMk/JTG2xFqh2gZWINGvdHNvUq3I0AAACPAAAAB3NzaC1yc2EAAACAMLaO4R+NC+dn7lxnEkERyahYlXsOaHExuPWAFVrQcSKtR+I7ldAF/XU4Ufwi+HbDQb59FLNHvdmq5W+5mCv8R9c6pYrLDc62ZyrX5xY6SzN8DyT+P2hVszug76xWAo7RNeId+lCGzYOrIGnAD/rIK6atFP7h18IP2Qo1+JrPgYM=`)

	if !bytes.Equal(expected, buf) {
		t.Errorf("expected %x, got %x", expected, buf)
	}

	krl2, err := ParseKRL(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(krl, krl2) {
		t.Errorf("expected %v, got %v", krl, krl2)
	}
	sigs := []ssh.PublicKey{cakey.PublicKey(), key1.PublicKey(), key2.PublicKey()}
	if !reflect.DeepEqual(sigs, krl2.SigningKeys) {
		t.Errorf("expected %v, got %v", sigs, krl2.SigningKeys)
	}
}

var parseErrors = [][]byte{
	MustUnhex(``),
	MustUnhex(`5353484b524c0a00000000010000000043b9a3550000000043b9a355000000000000000000000000000000`),
	MustUnhex(`5353484b524c0a00000000030000000043b9a3550000000043b9a35500000000000000000000000000000000`),
	MustUnhex(`ff53484b524c0a00000000010000000043b9a3550000000043b9a35500000000000000000000000000000000`),
	MustUnhex(`5353484b524c0a00000000010000000043b9a3550000000043b9a3550000000000000000000000000000000001`),
	MustUnhex(`5353484b524c0a00000000010000000043b9a3550000000043b9a355000000000000000000000000000000004200000000`),
	MustUnhex(`5353484b524c0a00000000010000000043b9a3550000000043b9a355000000000000000000000000000000000400000001`),
	MustUnhex(`5353484b524c0a00000000010000000043b9a3550000000043b9a35500000000000000000000000000000000040000000400000007`),
	MustUnhex(`5353484b524c0a00000000010000000043b9a3550000000043b9a355000000000000000000000000000000000400000097000000077373682d727361000000030100010000008100aa28507872c5898cc95419d513f42a4b705fa0a212c5c8684d520375d88c5cb0d29cedb572cba9b07475e96e363511e7b0fb585ee9a3cc58db411abc3cd6e7c26d7d042a2ce842bd7af40522798680b9f1a54fdb598a80a170153995c8e3e63d411af5d436fdf2b9675c2e4bb3cc235a03e7f1955386aa5211ba919ecfb4137700000001`),
	MustUnhex(`5353484b524c0a00000000010000000043b9a3550000000043b9a355000000000000000000000000000000000400000097000000077373682d727361000000030100010000008100aa28507872c5898cc95419d513f42a4b705fa0a212c5c8684d520375d88c5cb0d29cedb572cba9b07475e96e363511e7b0fb585ee9a3cc58db411abc3cd6e7c26d7d042a2ce842bd7af40522798680b9f1a54fdb598a80a170153995c8e3e63d411af5d436fdf2b9675c2e4bb3cc235a03e7f1955386aa5211ba919ecfb4137700000000`),
	MustUnhex(`5353484b524c0a00000000010000000043b9a3550000000043b9a355000000000000000000000000000000000400000097000000077373682d727361000000030100010000008100aa28507872c5898cc95419d513f42a4b705fa0a212c5c8684d520375d88c5cb0d29cedb572cba9b07475e96e363511e7b0fb585ee9a3cc58db411abc3cd6e7c26d7d042a2ce842bd7af40522798680b9f1a54fdb598a80a170153995c8e3e63d411af5d436fdf2b9675c2e4bb3cc235a03e7f1955386aa5211ba919ecfb413770000008f000000077373682d727361000000803211e50a9e42de8459d1e0b50f6acb165541f1848c3583867bfbbe2ff2cfaf5f61487f710c7cefa58aa1f49b89c194f47184e10363deb55b307bb0043309d2c04ba1582e0f75a4bc803ab6bc64fd47e9c748e9d8d6f79db560e756e4d1c4cef342f94ed913977d2c43e66fced841ea59a8d9eb3dc5ecbef3af2b182d1d1f1c04`),
}

func TestKRLParseErrors(t *testing.T) {
	t.Parallel()

	for _, buf := range parseErrors {
		_, err := ParseKRL(buf)
		if err == nil {
			t.Errorf("expected error on input: %x", buf)
		}
	}
}
