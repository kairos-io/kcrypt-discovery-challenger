package challenger

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/go-logr/logr"

	keyserverv1alpha1 "github.com/kairos-io/kairos-challenger/api/v1alpha1"
	"github.com/kairos-io/kairos-challenger/pkg/constants"
	"github.com/kairos-io/kairos-challenger/pkg/payload"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/kairos-io/kairos-challenger/controllers"
	tpm "github.com/kairos-io/tpm-helpers"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/gorilla/websocket"
)

// PassphraseRequestData is a struct that holds all the information needed in
// order to lookup a passphrase for a specific tpm hash.
type PassphraseRequestData struct {
	TPMHash    string
	Label      string
	DeviceName string
	UUID       string
}

type SealedVolumeData struct {
	Quarantined bool
	SecretName  string
	SecretPath  string

	PartitionLabel string
	VolumeName     string
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

func cleanKubeName(s string) (d string) {
	d = strings.ReplaceAll(s, "_", "-")
	d = strings.ToLower(d)
	return
}

func (s SealedVolumeData) DefaultSecret() (string, string) {
	secretName := fmt.Sprintf("%s-%s", s.VolumeName, s.PartitionLabel)
	secretPath := "passphrase"
	if s.SecretName != "" {
		secretName = s.SecretName
	}
	if s.SecretPath != "" {
		secretPath = s.SecretPath
	}
	return cleanKubeName(secretName), cleanKubeName(secretPath)
}

func writeRead(conn *websocket.Conn, input []byte) ([]byte, error) {
	writer, err := conn.NextWriter(websocket.BinaryMessage)
	if err != nil {
		return nil, err
	}

	if _, err := writer.Write(input); err != nil {
		return nil, err
	}

	if err := writer.Close(); err != nil {
		return nil, err
	}

	_, reader, err := conn.NextReader()
	if err != nil {
		return nil, err
	}

	return ioutil.ReadAll(reader)
}

func getPubHash(token string) (string, error) {
	ek, _, err := tpm.GetAttestationData(token)
	if err != nil {
		return "", err
	}

	return tpm.DecodePubHash(ek)
}

func Start(ctx context.Context, logger logr.Logger, kclient *kubernetes.Clientset, reconciler *controllers.SealedVolumeReconciler, namespace, address string) {
	logger.Info("Challenger started", "address", address)
	s := http.Server{
		Addr:         address,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	m := http.NewServeMux()

	m.HandleFunc("/postPass", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			logger.Error(err, "upgrading connection")
			return
		}
		defer func() {
			err := conn.Close()
			if err != nil {
				logger.Error(err, "closing the connection")
			}
		}()

		logger.Info("Receiving passphrase")
		if err := tpm.AuthRequest(r, conn); err != nil {
			errorMessage(conn, logger, err, "auth request")
			return
		}
		logger.Info("[Receiving passphrase] auth succeeded")

		token := r.Header.Get("Authorization")
		hashEncoded, err := getPubHash(token)
		if err != nil {
			errorMessage(conn, logger, err, "decoding pubhash")
			return
		}
		logger.Info("[Receiving passphrase] pubhash", "encodedhash", hashEncoded)

		label := r.Header.Get("label")
		name := r.Header.Get("name")
		uuid := r.Header.Get("uuid")
		v := &payload.Data{}
		logger.Info("Reading request data", "label", label, "name", name, "uuid", uuid)

		volumeList := &keyserverv1alpha1.SealedVolumeList{}
		for {
			if err := reconciler.List(ctx, volumeList, &client.ListOptions{Namespace: namespace}); err != nil {
				logger.Error(err, "listing volumes")
				continue
			}
			break
		}

		logger.Info("Looking up volume with request data")
		sealedVolumeData := findVolumeFor(PassphraseRequestData{
			TPMHash:    hashEncoded,
			Label:      label,
			DeviceName: name,
			UUID:       uuid,
		}, volumeList)

		if sealedVolumeData == nil {
			errorMessage(conn, logger, fmt.Errorf("no TPM Hash found for %s", hashEncoded), "")
			return
		}
		logger.Info("[Looking up volume with request data] succeeded")

		if err := conn.ReadJSON(v); err != nil {
			logger.Error(err, "reading json from connection")
			return
		}

		if !v.HasPassphrase() {
			errorMessage(conn, logger, fmt.Errorf("invalid answer from client: doesn't contain any passphrase"), "")
		}
		if v.HasError() {
			errorMessage(conn, logger, fmt.Errorf("error: %s", v.Error), v.Error)
		}

		secretName, secretPath := sealedVolumeData.DefaultSecret()
		logger.Info("Looking up secret in with name", "name", secretName, "namespace", namespace)
		_, err = kclient.CoreV1().Secrets(namespace).Get(ctx, secretName, v1.GetOptions{})
		if err == nil {
			logger.Info("Posted for already existing secret - ignoring")
			return
		}
		if !apierrors.IsNotFound(err) {
			errorMessage(conn, logger, err, "failed getting secret")
			return
		}

		logger.Info("secret not found, creating one")
		secret := corev1.Secret{
			TypeMeta: v1.TypeMeta{
				Kind:       "Secret",
				APIVersion: "apps/v1",
			},
			ObjectMeta: v1.ObjectMeta{
				Name:      secretName,
				Namespace: namespace,
			},
			StringData: map[string]string{
				secretPath:               v.Passphrase,
				constants.GeneratedByKey: v.GeneratedBy,
			},
			Type: "Opaque",
		}
		_, err = kclient.CoreV1().Secrets(namespace).Create(ctx, &secret, v1.CreateOptions{})
		if err != nil {
			errorMessage(conn, logger, err, "failed during secret creation")
		}
		logger.Info("created new secret")
	})

	m.HandleFunc("/getPass", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			logger.Error(err, "upgrading connection")
			return
		}
		defer func() {
			err := conn.Close()
			if err != nil {
				logger.Error(err, "closing the connection")
			}
		}()

		logger.Info("Received connection")
		volumeList := &keyserverv1alpha1.SealedVolumeList{}
		for {
			if err := reconciler.List(ctx, volumeList, &client.ListOptions{Namespace: namespace}); err != nil {
				logger.Error(err, "listing volumes")
				continue
			}
			break
		}

		logger.Info("reading data from request")
		token := r.Header.Get("Authorization")
		label := r.Header.Get("label")
		name := r.Header.Get("name")
		uuid := r.Header.Get("uuid")

		tokenStr := "empty"
		if token != "" {
			tokenStr = "not empty"
		}
		logger.Info("request data", "token", tokenStr, "label", label, "name", name, "uuid", uuid)

		if err := tpm.AuthRequest(r, conn); err != nil {
			logger.Error(err, "error validating challenge")
			return
		}

		hashEncoded, err := getPubHash(token)
		if err != nil {
			logger.Error(err, "error decoding pubhash")
			return
		}

		logger.Info("Looking up volume with request data")
		sealedVolumeData := findVolumeFor(PassphraseRequestData{
			TPMHash:    hashEncoded,
			Label:      label,
			DeviceName: name,
			UUID:       uuid,
		}, volumeList)

		if sealedVolumeData == nil {
			errorMessage(conn, logger, fmt.Errorf("no volume found with data from request and hash: %s", hashEncoded), "")
			return
		}
		logger.Info("[Looking up volume with request data] succeeded")

		if sealedVolumeData.Quarantined {
			errorMessage(conn, logger, fmt.Errorf("quarantined: %s", sealedVolumeData.PartitionLabel), "")
			return
		}

		secretName, secretPath := sealedVolumeData.DefaultSecret()

		// 1. The admin sets a specific cleartext password from Kube manager
		//      SealedVolume -> with a secret .
		// 2. The admin just adds a SealedVolume associated with a TPM Hash ( you don't provide any passphrase )
		// 3. There is no challenger server at all (offline mode)
		//
		logger.Info(fmt.Sprintf("looking up secret %s in namespace %s", secretName, namespace))
		secret, err := kclient.CoreV1().Secrets(namespace).Get(ctx, secretName, v1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				errorMessage(conn, logger, fmt.Errorf("No secret found for %s and %s", hashEncoded, sealedVolumeData.PartitionLabel), "")
			} else {
				errorMessage(conn, logger, err, "getting the secret from Kubernetes")
			}

			return
		}
		logger.Info(fmt.Sprintf("secret %s found in namespace %s", secretName, namespace))

		passphrase := secret.Data[secretPath]
		generatedBy := secret.Data[constants.GeneratedByKey]

		writer, err := conn.NextWriter(websocket.BinaryMessage)
		if err != nil {
			logger.Error(err, "getting a writer from the connection")
		}
		p := payload.Data{Passphrase: string(passphrase), GeneratedBy: string(generatedBy)}
		err = json.NewEncoder(writer).Encode(p)
		if err != nil {
			logger.Error(err, "writing passphrase to the websocket channel")
		}
		if err = writer.Close(); err != nil {
			logger.Error(err, "closing the writer")
			return
		}
	})

	s.Handler = logRequestHandler(logger, m)

	go func() {
		err := s.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			panic(err)
		}
	}()

	go func() {
		<-ctx.Done()
		s.Shutdown(ctx)
	}()
}

func findVolumeFor(requestData PassphraseRequestData, volumeList *keyserverv1alpha1.SealedVolumeList) *SealedVolumeData {
	for _, v := range volumeList.Items {
		if requestData.TPMHash == v.Spec.TPMHash {
			for _, p := range v.Spec.Partitions {
				deviceNameMatches := requestData.DeviceName != "" && p.DeviceName == requestData.DeviceName
				uuidMatches := requestData.UUID != "" && p.UUID == requestData.UUID
				labelMatches := requestData.Label != "" && p.Label == requestData.Label
				secretName := ""
				if p.Secret != nil && p.Secret.Name != "" {
					secretName = p.Secret.Name
				}
				secretPath := ""
				if p.Secret != nil && p.Secret.Path != "" {
					secretPath = p.Secret.Path
				}
				if labelMatches || uuidMatches || deviceNameMatches {
					return &SealedVolumeData{
						Quarantined:    v.Spec.Quarantined,
						SecretName:     secretName,
						SecretPath:     secretPath,
						VolumeName:     v.Name,
						PartitionLabel: p.Label,
					}
				}
			}
		}
	}

	return nil
}

// errorMessage should be used when an error should be both, printed to the stdout
// and sent over the wire to the websocket client.
func errorMessage(conn *websocket.Conn, logger logr.Logger, theErr error, description string) {
	if theErr == nil {
		return
	}
	logger.Error(theErr, description)

	writer, err := conn.NextWriter(websocket.BinaryMessage)
	if err != nil {
		logger.Error(err, "getting a writer from the connection")
	}

	errMsg := theErr.Error()
	err = json.NewEncoder(writer).Encode(payload.Data{Error: errMsg})
	if err != nil {
		logger.Error(err, "error encoding the response to json")
	}
	err = writer.Close()
	if err != nil {
		logger.Error(err, "closing the writer")
	}
}

func logRequestHandler(logger logr.Logger, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Info("Incoming request", "method", r.Method, "uri", r.URL.String(),
			"referer", r.Header.Get("Referer"), "userAgent", r.Header.Get("User-Agent"))

		h.ServeHTTP(w, r)
	})
}
