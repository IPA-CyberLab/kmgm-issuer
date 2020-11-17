/*
Copyright 2020 IPA CyberLab.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/serve/testserver"
	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/testkmgm"
	"github.com/IPA-CyberLab/kmgm/pemparser"
	"github.com/IPA-CyberLab/kmgm/testutils"
	"github.com/google/go-cmp/cmp"
	certmanageriov1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	certmanageriometav1 "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"go.uber.org/zap"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	kmgmissuerv1beta1 "github.com/IPA-CyberLab/kmgm-issuer/api/v1beta1"
	"github.com/IPA-CyberLab/kmgm-issuer/controllers"
	testlogger "github.com/IPA-CyberLab/kmgm-issuer/test/logger"
	// +kubebuilder:scaffold:imports
)

func testClient(t *testing.T) *rest.Config {
	t.Helper()
	testEnv := &envtest.Environment{
		CRDDirectoryPaths: []string{
			filepath.Join("..", "config", "crd"),
			filepath.Join("..", "test", "testdata", "crd"),
		},
	}
	t.Cleanup(func() {
		if err := testEnv.Stop(); err != nil {
			t.Errorf("testEnv.Stop non-nil err: %v", err)
		}
	})

	var err error
	cfg, err := testEnv.Start()
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	if err := kmgmissuerv1beta1.AddToScheme(scheme.Scheme); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if err = certmanageriov1.AddToScheme(scheme.Scheme); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// +kubebuilder:scaffold:scheme

	return cfg
}

func RetryUntil(t *testing.T, deadline time.Time, f func() error) {
	t.Helper()

	start := time.Now()

	var err error
	for ; time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		err = f()
		if err == nil {
			t.Logf("Took %v to satisfy condition.", time.Since(start))
			return
		}
	}
	t.Errorf("Failed to satisfy condition: %v", err)
}

func runManager(t *testing.T, cfg *rest.Config, logger *zap.Logger) chan struct{} {
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if err := (&controllers.CertificateRequestReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("CertificateRequest"),
		ZapLog: logger,
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if err := (&controllers.IssuerReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("Issuer"),
		ZapLog: logger,
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	closeCh := make(chan struct{})
	go func() {
		if err := mgr.Start(closeCh); err != nil {
			t.Logf("unexpected err: %v", err)
		}
	}()
	t.Logf("mgr start")

	return closeCh
}

type Env struct {
	testserver *testserver.TestServer
	logger     *testlogger.TestLogger
	cli        client.Client
	closeCh    chan struct{}
}

func setupEnv(t *testing.T) *Env {
	ts := testserver.Run(t, testserver.RunSetup)

	logger := testlogger.New()
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		for _, l := range logger.Logs.All() {
			t.Logf("🐕%+v", l)
		}
	})

	cfg := testClient(t)

	closeCh := runManager(t, cfg, logger.Logger)

	cli, err := client.New(cfg, client.Options{Scheme: scheme.Scheme})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	e := &Env{
		testserver: ts,
		logger:     logger,
		cli:        cli,
		closeCh:    closeCh,
	}
	t.Cleanup(func() {
		if e.closeCh != nil {
			close(closeCh)
		}
	})
	return e
}

func (env *Env) CreateIssuer(t *testing.T, ctx context.Context, profile string) {
	if err := env.cli.Create(ctx, &kmgmissuerv1beta1.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-issuer",
			Namespace: "default",
		},
		Spec: kmgmissuerv1beta1.IssuerSpec{
			HostPort:     env.testserver.AddrPort,
			PinnedPubKey: env.testserver.PubKeyHash,
			AccessToken:  testserver.BootstrapToken,
			Profile:      profile,
		},
	}); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
}

func (env *Env) WaitUntilIssuerReady(t *testing.T, ctx context.Context) {
	var issuer kmgmissuerv1beta1.Issuer
	RetryUntil(t, time.Now().Add(20*time.Second), func() error {
		if err := env.cli.Get(ctx, types.NamespacedName{
			Namespace: "default",
			Name:      "test-issuer",
		}, &issuer); err != nil {
			if !kerrors.IsNotFound(err) {
				t.Fatalf("unexpected err: %v", err)
			}
			return err
		}
		if !controllers.IssuerIsReady(&issuer) {
			return errors.New("Not ready")
		}

		return nil
	})
	t.Logf("%v", issuer)
}

func (env *Env) CreateCertificateRequest(t *testing.T, ctx context.Context, name string, req *x509.CertificateRequest, priv crypto.PrivateKey) {
	der, err := x509.CreateCertificateRequest(rand.Reader, req, priv)
	if err != nil {
		t.Fatalf("Unexpected err: %v", err)
	}
	csrpem := pemparser.MarshalCertificateRequestDer(der)

	env.CreateCertificateRequestPEM(t, ctx, name, csrpem)
}

func (env *Env) CreateCertificateRequestPEM(t *testing.T, ctx context.Context, name string, pem []byte) {
	if err := env.cli.Create(ctx, &certmanageriov1.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
		},
		Spec: certmanageriov1.CertificateRequestSpec{
			// Duration: &metav1.Duration{
			// 	Duration: 0,
			// },
			IssuerRef: certmanageriometav1.ObjectReference{
				Name:  "test-issuer",
				Kind:  "Issuer",
				Group: kmgmissuerv1beta1.GroupVersion.Group,
			},
			Request: pem,
			IsCA:    false,
			// Usages: []KeyUsage,
		},
	}); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
}

func (env *Env) WaitUntilCertificateRequestReady(t *testing.T, ctx context.Context, name string) *certmanageriov1.CertificateRequest {
	var certreq certmanageriov1.CertificateRequest
	RetryUntil(t, time.Now().Add(20*time.Second), func() error {
		if err := env.cli.Get(ctx, types.NamespacedName{
			Namespace: "default",
			Name:      name,
		}, &certreq); err != nil {
			if !kerrors.IsNotFound(err) {
				t.Fatalf("unexpected err: %v", err)
			}
			return err
		}
		conds := controllers.GetCertificateRequestConditions(&certreq)
		if !conds.IsReady() {
			return errors.New("Not ready")
		}

		return nil
	})
	t.Logf("%v", certreq)

	return &certreq
}

func TestIssue(t *testing.T) {
	ctx := context.Background()
	env := setupEnv(t)

	env.CreateIssuer(t, ctx, "")
	env.WaitUntilIssuerReady(t, ctx)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Unexpected err: %v", err)
	}
	testDNSNames := []string{"foo.example", "hoge.fuga.example"}
	testIPAddrs := []net.IP{
		net.ParseIP("2001:DB8::1234"),
		net.ParseIP("192.0.2.0"),
	}

	t.Run("basic", func(t *testing.T) {
		env.CreateCertificateRequest(t, ctx, "test-request",
			&x509.CertificateRequest{
				// SignatureAlgorithm -> rely on x509.CreateCertificateRequest autofill

				Subject: pkix.Name{
					Country:      []string{"JP"},
					Organization: []string{"testorg"},
					CommonName:   "testcn",
				},
				DNSNames: testDNSNames,
				// EmailAddresses:  nil, // unsupported
				IPAddresses: testIPAddrs,
				// URIs:            nil, // unsupported
				ExtraExtensions: nil,
				Attributes:      nil,
			}, priv)
		certreq := env.WaitUntilCertificateRequestReady(t, ctx, "test-request")

		certpem := certreq.Status.Certificate
		certs, err := pemparser.ParseCertificates(certpem)
		if err != nil {
			t.Fatalf("Unexpected err: %v", err)
		}
		if len(certs) != 1 {
			t.Fatalf("Unexpected num certs: %d", len(certs))
		}
		cert := certs[0]

		if diff := cmp.Diff(testDNSNames, cert.DNSNames); diff != "" {
			t.Errorf("DNSNames diff: %s", diff)
		}
		if diff := cmp.Diff(testIPAddrs, cert.IPAddresses); diff != "" {
			t.Errorf("IPAddrs diff: %s", diff)
		}
		if cert.KeyUsage != x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment {
			t.Errorf("Unexpected KeyUsage: %v", cert.KeyUsage)
		}
		if diff := cmp.Diff(cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}); diff != "" {
			t.Errorf("Unexpected ExtKeyUsage diff: %s", diff)
		}

		capem := certreq.Status.CA
		cacerts, err := pemparser.ParseCertificates(capem)
		if err != nil {
			t.Fatalf("Unexpected err: %v", err)
		}
		if len(cacerts) != 1 {
			t.Fatalf("Unexpected num certs: %d", len(cacerts))
		}
		cacert := cacerts[0]

		certpool := x509.NewCertPool()
		certpool.AddCert(cacert)

		if _, err := cert.Verify(x509.VerifyOptions{
			Roots:       certpool,
			KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			CurrentTime: time.Now(),
		}); err != nil {
			t.Fatalf("cert verify failed: %v", err)
		}
	})

	t.Run("2048bit RSA", func(t *testing.T) {
		pem := []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIICfzCCAWcCAQAwADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL7Q
8bAFUqalFuVFwsThSZ/YxsUpfBVqc8RHmfhz/eMfnzIH5G+DI9PoGzw6eV2smzig
cNvRh/gLmCL8u/muUENNegc5PY4MwuL8D4lhBCQQ4/Pb2VoillUtYChCgczqMzgg
dCwCUsxYMcrt2YrmFK4Kq9NcjYRWn4Apg2VX9OKPGzzgxYD9VXLWuUOCd0S1NsTD
O+Gl/3KtibS39AysNh3luK+a5NvFp7p35EE/mnlBxvt5nmIbqLWjGCeBTpkLP06p
B7Yw75D7nbAJWfYlBjeIoO9RF/SE8rRHwx1SMJVLq0IQCX+EdeNMRGn9d3KM3n9g
rmLAyLB+hjZhi4828LkCAwEAAaA6MDgGCSqGSIb3DQEJDjErMCkwGgYDVR0RBBMw
EYIPcnNhNDA5Ni5leGFtcGxlMAsGA1UdDwQEAwIFoDANBgkqhkiG9w0BAQsFAAOC
AQEAr+V0THiWNaYbNpDjEcNVJECisaDRtHW0cKkmDpaxlXGLoPyY5RJi6ru5+ryO
IdC/fb5zku2tN0XkVC5enSgI0rbYj2cU5MvIQzLXY+yGAbL8cSeyCvWHM4PrUKKo
MjFDuv0hmmi1xM9s/qqtsnRe8qnE/f/DYaAQFCwzCJpwvoOvtJjLDvlg3siH9yzt
5N2S8KAWbOnqNOvXTsOaeomd4Fusrzbot4DsAMITcDcCyKusj+bfdtDLQPeEDwVz
UF2MIYej/WY4QHQS0UtCQv0gMjx/8b+DLdVQtlzBGq4aoPPvDoj//zC77ZbXnt+0
DGoupviObCSS6FWtR2wHKHTrRQ==
-----END CERTIFICATE REQUEST-----
`)
		env.CreateCertificateRequestPEM(t, ctx, "test-request-rsa2048", pem)
		certreq := env.WaitUntilCertificateRequestReady(t, ctx, "test-request-rsa2048")

		certpem := certreq.Status.Certificate
		certs, err := pemparser.ParseCertificates(certpem)
		if err != nil {
			t.Fatalf("Unexpected err: %v", err)
		}
		if len(certs) != 1 {
			t.Fatalf("Unexpected num certs: %d", len(certs))
		}
		cert := certs[0]

		if cert.PublicKeyAlgorithm != x509.RSA {
			t.Errorf("Unexpected PublicKeyAlgorithm: %v", cert.PublicKeyAlgorithm)
		}
		rsapk, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			t.Fatalf("Failed to extract pub key")
		}
		if rsapk.N.BitLen() != 2048 {
			t.Errorf("unexpected key size: %d", rsapk.Size())
		}
	})

	t.Run("keyusage", func(t *testing.T) {
		pem := []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIIElTCCAn0CAQAwADCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANic
UU1j/mIJbcZCIfthXW43EIhEYrWC4JzeGWY2Dj2VJKjiAa+dpgL8FJsKD+RXEE8F
rlS/rYZVelin9GMrOVG10vueLIy686zOstfTOkJMk6JSF+APf1qlAlHEblWvfL2E
uHXY+WIzAQnoXqljFWgwh3TJEj52bQTxchd6uaVrCMHtbhUABkaZagI3AtGa1mfP
67ICGKBYwpYVvXp5mm2LHpkMTTYWJjMTqBIga46fXJHsmxtCoLKOMYLmRLakYtvf
zLXMKcoDh8C6DAV1rBoWnfcxaIF431Il9Ujv14JZGlJr15nQbvFImkAGIGGRz7sG
DogLEcYebgQwbqAt+3Kub76YfYI2fHcxh8QRWm7R8pbuKnDZdhXlboXJa0zltX1t
3mXtMxA3l19wdM573bx3zBsh4ZYhDcQfy2dGPeZdmo2zQXob7cVBPEfNrGuGF4ye
hSUUuxZcIWv2Ag7PrPt5gTepPFqxlshKicdv0NWYn+1ZDNcaFKGTr6aryGYUs9EH
qqvMXjB9yZHALaD/cVuCgq4zphhKfXXqoYYJku0DKYMqXwesz4nY0AALojHhG1TB
EzF6vzyYqX/t37Bu4QLMk8GEU64mMBiSvreSagB7y83tG7SAANuLW4wrmDZr//K+
Q3aH4dv9VHexFIJ4DyPqYLbDzhzB6WkZx8olAIMBAgMBAAGgUDBOBgkqhkiG9w0B
CQ4xQTA/MBsGA1UdEQQUMBKCEGtleXVzYWdlLmV4YW1wbGUwCwYDVR0PBAQDAgWg
MBMGA1UdJQQMMAoGCCsGAQUFBwMBMA0GCSqGSIb3DQEBCwUAA4ICAQA6i3FbMJiz
oa8x2oqsxFksOqQPYLRLzhT1TtEV2zh9wvDjYUR1QdDlsfNyftoGW/VU6N0X/UHm
4arhPoNV4SSDKlY0aPj6wpMLx7+Px232G1m7BOlBcy3BtRrC+/yQHKup61J+zykX
oCzUHxOC6GFj6+5kUi7Tm8kbEXZ0qQVpVgHc2kPxId4tu0RTJxXXkHRY3Jl9uwHx
TIbXlpaKAGNLGj8952bAq3P+51KsLlXoGA+ujNPeC4bp0W6I1A/3LEueeWZ+ine6
1lVbi8Or2L+K4RD0+NWl3a+wzGzyTU6JV0u4kD+LZVYSmWUBcSrDCbbveUh+9bdE
9cc6pVivxLujHAU2rljx1DOlF6UeJ/sH37uJqc9wqrdAttlstlju9UEev6XirHUa
OF9qcDJoL9uDTESy7uMRtZZr0sj36v3kWc2vJHu5GUhIm9P97XTmAvoUX4GR+9xv
VQJYtJHtFkXsys/yKM0PG6Xs3J8LaraxcHRpkN18oN1XjhX8lx47NAw1f5kwN8zw
cUMc9kESbF+BHs5QMAuRCpPNpbbFnVj3kd3JvFAeDeSGlpl5werdg2wX5TNuARi8
MEqii1NZfnAZBNMZ3hHhuZfnejPzv+v+ENF435cB4z0XrEYJY4UC5kPGx1wl3fO1
RMAREVAAiTfzHv8Tz1hK3veniICEM/qVcA==
-----END CERTIFICATE REQUEST-----`)
		env.CreateCertificateRequestPEM(t, ctx, "test-request-keyusage", pem)
		certreq := env.WaitUntilCertificateRequestReady(t, ctx, "test-request-keyusage")

		certpem := certreq.Status.Certificate
		certs, err := pemparser.ParseCertificates(certpem)
		if err != nil {
			t.Fatalf("Unexpected err: %v", err)
		}
		if len(certs) != 1 {
			t.Fatalf("Unexpected num certs: %d", len(certs))
		}
		cert := certs[0]

		if cert.KeyUsage != x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment {
			t.Errorf("Unexpected KeyUsage: %v", cert.KeyUsage)
		}
		if diff := cmp.Diff(cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}); diff != "" {
			t.Errorf("Unexpected ExtKeyUsage diff: %s", diff)
		}
	})

	t.Run("ecdsa", func(t *testing.T) {
		pem := []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIHzMIGaAgEAMAAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQzH2cBP3lcXHwm
451JhOmDRq1Y/ZbNgw00r5mSf5r9hqR/Xd+30QhiHOrCA7LfE0vKCNuidndDTH8Q
95VrjM8ooDgwNgYJKoZIhvcNAQkOMSkwJzAYBgNVHREEETAPgg1lY2RzYS5leGFt
cGxlMAsGA1UdDwQEAwIFoDAKBggqhkjOPQQDAgNIADBFAiEAsEvJuhNtieOyEmqN
lXabDvu2IoDqCshBpwyjsvy+rTUCIAW/Dn80lqxR2YQiMYujLxP84EOPZfwY1e7p
bVOc8KNA
-----END CERTIFICATE REQUEST-----`)
		if _, err := pemparser.ParseCertificateRequest(pem); err != nil {
			t.Fatalf("err: %v", err)
		}

		env.CreateCertificateRequestPEM(t, ctx, "test-request-ecdsa", pem)
		certreq := env.WaitUntilCertificateRequestReady(t, ctx, "test-request-ecdsa")

		certpem := certreq.Status.Certificate
		certs, err := pemparser.ParseCertificates(certpem)
		if err != nil {
			t.Fatalf("Unexpected err: %v", err)
		}
		if len(certs) != 1 {
			t.Fatalf("Unexpected num certs: %d", len(certs))
		}
		cert := certs[0]

		// signature algorithm is CA cert RSA4096's
		if cert.SignatureAlgorithm != x509.SHA256WithRSA {
			t.Errorf("Unexpected signature algorithm: %v", cert.SignatureAlgorithm)
		}

		if cert.PublicKeyAlgorithm != x509.ECDSA {
			t.Errorf("Unexpected public key algorithm: %v", cert.PublicKeyAlgorithm)
		}
	})
}

func TestSpecifyProfile(t *testing.T) {
	ctx := context.Background()
	env := setupEnv(t)

	yaml := []byte(`
noDefault: true

setup:
  subject:
    commonName: myCA
  keyType: ecdsa
  validity: farfuture
`)
	logs, err := testkmgm.Run(t, context.Background(), env.testserver.Basedir, yaml, []string{"--profile", "myprofile", "setup"}, testkmgm.NowDefault)
	testutils.ExpectErr(t, err, nil)
	testutils.ExpectLogMessage(t, logs, "CA setup successfully completed")

	env.CreateIssuer(t, ctx, "myprofile")
	env.WaitUntilIssuerReady(t, ctx)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Unexpected err: %v", err)
	}
	env.CreateCertificateRequest(t, ctx, "cr-specify-profile", &x509.CertificateRequest{
		Subject: pkix.Name{
			Country:      []string{"JP"},
			Organization: []string{"testorg"},
			CommonName:   "testcn",
		},
	}, priv)
	certreq := env.WaitUntilCertificateRequestReady(t, ctx, "cr-specify-profile")

	certpem := certreq.Status.Certificate
	certs, err := pemparser.ParseCertificates(certpem)
	if err != nil {
		t.Fatalf("Unexpected err: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("Unexpected num certs: %d", len(certs))
	}
	cert := certs[0]

	if cert.Subject.String() != "CN=testcn,O=testorg,C=JP" {
		t.Errorf("Unexpected Subject: %v", cert.Subject)
	}
	if cert.Issuer.String() != "CN=myCA" {
		t.Errorf("Unexpected Issuer: %v", cert.Issuer)
	}
}

func TestCertificateRequestBeforeIssuer(t *testing.T) {
	ctx := context.Background()
	env := setupEnv(t)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Unexpected err: %v", err)
	}
	env.CreateCertificateRequest(t, ctx, "cr-before-issuer", &x509.CertificateRequest{
		Subject: pkix.Name{
			Country:      []string{"JP"},
			Organization: []string{"testorg"},
			CommonName:   "testcn",
		},
	}, priv)

	env.CreateIssuer(t, ctx, "")
	env.WaitUntilIssuerReady(t, ctx)

	certreq := env.WaitUntilCertificateRequestReady(t, ctx, "cr-before-issuer")

	certpem := certreq.Status.Certificate
	certs, err := pemparser.ParseCertificates(certpem)
	if err != nil {
		t.Fatalf("Unexpected err: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("Unexpected num certs: %d", len(certs))
	}
	cert := certs[0]

	if cert.Subject.String() != "CN=testcn,O=testorg,C=JP" {
		t.Errorf("Unexpected Subject: %v", cert.Subject)
	}
}
