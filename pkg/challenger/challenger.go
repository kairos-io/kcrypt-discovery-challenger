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
	"github.com/kairos-io/kairos-challenger/pkg/payload"

	"github.com/kairos-io/kairos-challenger/controllers"
	tpm "github.com/kairos-io/tpm-helpers"
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

func getPubHashFromEK(ekBytes []byte) (string, error) {
	// Need to decode the EK bytes first to get the proper EK structure
	ek, err := tpm.DecodeEK(ekBytes)
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

	// TPM Attestation WebSocket endpoint
	m.HandleFunc("/tpm-attestation", func(w http.ResponseWriter, r *http.Request) {
		handleTPMAttestation(w, r, logger, reconciler, kclient, namespace)
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

// handleTPMAttestation handles the TPM attestation flow using WebSocket protocol
func handleTPMAttestation(w http.ResponseWriter, r *http.Request, logger logr.Logger, reconciler *controllers.SealedVolumeReconciler, kclient *kubernetes.Clientset, namespace string) {
	logger.V(1).Info("Debug: Attempting to upgrade HTTP connection to WebSocket", "remoteAddr", r.RemoteAddr)
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logger.Error(err, "upgrading connection for TPM attestation")
		return
	}
	defer func() {
		err := conn.Close()
		if err != nil {
			logger.Error(err, "closing the connection")
		}
	}()

	logger.Info("Starting TPM attestation WebSocket flow")

	// Get partition details from headers (sent by client)
	label := r.Header.Get("label")
	name := r.Header.Get("name")
	uuid := r.Header.Get("uuid")
	logger.Info("Partition details from client", "label", label, "name", name, "uuid", uuid)

	// TODO: Implement complete WebSocket TPM attestation protocol
	// This requires:
	// 1. Get client's attestation data (EK + AttestationParameters)
	// 2. Generate challenge using go-attestation native types
	// 3. Send AttestationChallengeResponse to client
	// 4. Wait for ProofRequest from client
	// 5. Validate challenge response
	// 6. TOFU: Generate/retrieve passphrase (requires SealedVolume CRD changes)
	// 7. Send ProofResponse with passphrase

	logger.Info("TPM attestation protocol implementation incomplete - requires SealedVolume CRD changes for TOFU")

	// For now, just send an error response
	errorMessage(conn, logger, fmt.Errorf("TPM attestation protocol not yet implemented"), "WebSocket TPM attestation")
}
