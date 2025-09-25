package challenger

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/go-attestation/attest"

	keyserverv1alpha1 "github.com/kairos-io/kairos-challenger/api/v1alpha1"

	"github.com/kairos-io/kairos-challenger/controllers"
	tpm "github.com/kairos-io/tpm-helpers"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

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
	d = strings.ReplaceAll(d, "/", "-") // Replace forward slashes with hyphens
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

// isConnectionClosed checks if the error is about an already closed connection
func isConnectionClosed(err error) bool {
	return strings.Contains(err.Error(), "use of closed network connection") ||
		strings.Contains(err.Error(), "connection closed")
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

// generateTOFUPassphrase creates a cryptographically secure random passphrase for TOFU enrollment
func generateTOFUPassphrase() (string, error) {
	// Generate 32 random bytes (256 bits) for strong passphrase
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("generating random passphrase: %w", err)
	}

	// Encode as base64 for safe storage and transmission
	passphrase := base64.StdEncoding.EncodeToString(randomBytes)
	return passphrase, nil
}

// createOrReuseTOFUSecret creates a Kubernetes secret containing the generated passphrase
// If a secret with the same name already exists, it returns the existing passphrase
// Returns the passphrase that should be used (either new or existing)
func createOrReuseTOFUSecret(kclient *kubernetes.Clientset, namespace, secretName, secretPath, passphrase string, logger logr.Logger) (string, error) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			secretPath: []byte(passphrase),
		},
	}

	_, err := kclient.CoreV1().Secrets(namespace).Create(context.TODO(), secret, metav1.CreateOptions{})
	if err != nil {
		if errors.IsAlreadyExists(err) {
			// Secret exists - this can happen when a SealedVolume was deleted but secret remained
			// Retrieve and return the existing passphrase
			logger.Info("Secret already exists, reusing existing secret", "secretName", secretName, "reason", "previous SealedVolume may have been deleted")

			existingSecret, getErr := kclient.CoreV1().Secrets(namespace).Get(context.TODO(), secretName, metav1.GetOptions{})
			if getErr != nil {
				return "", fmt.Errorf("retrieving existing secret: %w", getErr)
			}

			existingPassphrase, exists := existingSecret.Data[secretPath]
			if !exists || len(existingPassphrase) == 0 {
				return "", fmt.Errorf("existing secret does not contain expected passphrase data at path %s", secretPath)
			}

			logger.Info("Successfully retrieved passphrase from existing secret", "secretName", secretName)
			return string(existingPassphrase), nil
		}
		return "", fmt.Errorf("creating TOFU secret: %w", err)
	}

	logger.Info("Successfully created new TOFU secret", "secretName", secretName)
	return passphrase, nil
}

// createTOFUSealedVolumeWithPCRs creates a SealedVolume resource for automatic TOFU enrollment with PCR values
func createTOFUSealedVolumeWithPCRs(reconciler *controllers.SealedVolumeReconciler, namespace, tpmHash, secretName, secretPath string, partition PartitionInfo, ek *attest.EK, akParams *attest.AttestationParameters, pcrValues *keyserverv1alpha1.PCRValues) error {
	// Extract EK and AK public keys in PEM format
	ekPEM, err := encodeEKToPEM(ek)
	if err != nil {
		return fmt.Errorf("encoding EK to PEM: %w", err)
	}

	akPEM, err := encodeAKToPEM(akParams)
	if err != nil {
		return fmt.Errorf("encoding AK to PEM: %w", err)
	}

	// Use provided PCR values or empty if none provided
	if pcrValues == nil {
		pcrValues = &keyserverv1alpha1.PCRValues{}
	}

	currentTime := metav1.Now()

	sealedVolume := &keyserverv1alpha1.SealedVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cleanKubeName(fmt.Sprintf("tofu-%s", tpmHash[:8])),
			Namespace: namespace,
		},
		Spec: keyserverv1alpha1.SealedVolumeSpec{
			TPMHash: tpmHash,
			Partitions: []keyserverv1alpha1.PartitionSpec{
				{
					Label:      partition.Label,
					DeviceName: partition.DeviceName,
					UUID:       partition.UUID,
					Secret: &keyserverv1alpha1.SecretSpec{
						Name: secretName,
						Path: secretPath,
					},
				},
			},
			Quarantined: false,
			Attestation: &keyserverv1alpha1.AttestationSpec{
				EKPublicKey:    ekPEM,
				AKPublicKey:    akPEM,
				PCRValues:      pcrValues,
				EnrolledAt:     &currentTime,
				LastVerifiedAt: &currentTime,
			},
		},
	}

	return reconciler.Create(context.TODO(), sealedVolume)
}

// createTOFUSealedVolume creates a SealedVolume resource for automatic TOFU enrollment
func createTOFUSealedVolume(reconciler *controllers.SealedVolumeReconciler, namespace, tpmHash, secretName, secretPath string, partition PartitionInfo, ek *attest.EK, akParams *attest.AttestationParameters) error {
	// Extract EK and AK public keys in PEM format
	ekPEM, err := encodeEKToPEM(ek)
	if err != nil {
		return fmt.Errorf("encoding EK to PEM: %w", err)
	}

	akPEM, err := encodeAKToPEM(akParams)
	if err != nil {
		return fmt.Errorf("encoding AK to PEM: %w", err)
	}

	// For now, we'll store empty PCR values - they'll be populated on first successful attestation
	// In a production system, you might want to get actual PCR values during enrollment
	currentTime := metav1.Now()

	sealedVolume := &keyserverv1alpha1.SealedVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cleanKubeName(fmt.Sprintf("tofu-%s", tpmHash[:8])),
			Namespace: namespace,
		},
		Spec: keyserverv1alpha1.SealedVolumeSpec{
			TPMHash: tpmHash,
			Partitions: []keyserverv1alpha1.PartitionSpec{
				{
					Label:      partition.Label,
					DeviceName: partition.DeviceName,
					UUID:       partition.UUID,
					Secret: &keyserverv1alpha1.SecretSpec{
						Name: secretName,
						Path: secretPath,
					},
				},
			},
			Quarantined: false,
			Attestation: &keyserverv1alpha1.AttestationSpec{
				EKPublicKey:    ekPEM,
				AKPublicKey:    akPEM,
				PCRValues:      &keyserverv1alpha1.PCRValues{}, // Empty initially
				EnrolledAt:     &currentTime,
				LastVerifiedAt: &currentTime,
			},
		},
	}

	return reconciler.Create(context.TODO(), sealedVolume)
}

// createTOFUSealedVolumeWithAttestation creates a SealedVolume resource with pre-created attestation data
func createTOFUSealedVolumeWithAttestation(reconciler *controllers.SealedVolumeReconciler, namespace, tpmHash, secretName, secretPath string, partition PartitionInfo, attestation *keyserverv1alpha1.AttestationSpec) error {
	sealedVolume := &keyserverv1alpha1.SealedVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cleanKubeName(fmt.Sprintf("tofu-%s", tpmHash[:8])),
			Namespace: namespace,
		},
		Spec: keyserverv1alpha1.SealedVolumeSpec{
			TPMHash: tpmHash,
			Partitions: []keyserverv1alpha1.PartitionSpec{
				{
					Label:      partition.Label,
					DeviceName: partition.DeviceName,
					UUID:       partition.UUID,
					Secret: &keyserverv1alpha1.SecretSpec{
						Name: secretName,
						Path: secretPath,
					},
				},
			},
			Quarantined: false,
			Attestation: attestation,
		},
	}

	return reconciler.Create(context.TODO(), sealedVolume)
}

// PartitionInfo holds partition identification data from client headers
type PartitionInfo struct {
	Label      string
	DeviceName string
	UUID       string
}

// ClientAttestation holds all client-provided attestation data
type ClientAttestation struct {
	EK        *attest.EK
	AK        *attest.AttestationParameters
	PCRQuote  []byte
	PCRValues *keyserverv1alpha1.PCRValues
}

// EnrollmentContext represents the current enrollment state
type EnrollmentContext struct {
	IsNewEnrollment bool
	SealedVolume    *keyserverv1alpha1.SealedVolume
	VolumeData      *SealedVolumeData
	TPMHash         string
	Partition       PartitionInfo
}

// encodeEKToPEM converts an attest.EK to PEM format for storage
func encodeEKToPEM(ek *attest.EK) (string, error) {
	if ek.Certificate != nil {
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: ek.Certificate.Raw,
		}
		return string(pem.EncodeToMemory(pemBlock)), nil
	}

	data, err := pubBytesFromKey(ek.Public)
	if err != nil {
		return "", err
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: data,
	}
	return string(pem.EncodeToMemory(pemBlock)), nil
}

// encodeAKToPEM converts attestation parameters to PEM format for storage
func encodeAKToPEM(akParams *attest.AttestationParameters) (string, error) {

	// The akParams.Public contains raw TPMT_PUBLIC bytes from the TPM
	// We store these raw bytes in PEM format for enrollment record keeping
	// This enables TOFU verification and audit purposes using modern go-tpm v0.9.x API

	pemBlock := &pem.Block{
		Type:  "TPM ATTESTATION KEY",
		Bytes: akParams.Public,
	}
	return string(pem.EncodeToMemory(pemBlock)), nil
}

// pubBytesFromKey marshals a public key to DER format
func pubBytesFromKey(pub interface{}) ([]byte, error) {
	data, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("error marshaling public key: %v", err)
	}
	return data, nil
}

// verifyAKMatch compares the current AK public key with the enrolled one
func verifyAKMatch(sealedVolume *keyserverv1alpha1.SealedVolume, currentAK *attest.AttestationParameters, logger logr.Logger) error {
	// Get the stored AK from the SealedVolume's attestation spec
	if sealedVolume.Spec.Attestation == nil {
		return fmt.Errorf("no attestation data in SealedVolume for verification")
	}

	storedAKPEM := sealedVolume.Spec.Attestation.AKPublicKey
	if storedAKPEM == "" {
		return fmt.Errorf("no AK public key stored in SealedVolume for verification")
	}

	// Encode current AK to PEM for comparison
	currentAKPEM, err := encodeAKToPEM(currentAK)
	if err != nil {
		return fmt.Errorf("encoding current AK to PEM: %w", err)
	}

	// Compare the PEM-encoded AK public keys
	if storedAKPEM != currentAKPEM {
		logger.Info("AK mismatch detected",
			"storedAKLength", len(storedAKPEM),
			"currentAKLength", len(currentAKPEM))
		return fmt.Errorf("AK public key does not match enrolled key - potential TPM impersonation")
	}

	logger.Info("AK verification successful - matches enrolled key")
	return nil
}

// verifyPCRMatch compares current PCR values with enrolled ones
func verifyPCRMatch(sealedVolume *keyserverv1alpha1.SealedVolume, pcrQuote []byte, logger logr.Logger) error {
	// Extract current PCR values from the quote
	currentPCRs, err := extractPCRValues(pcrQuote)
	if err != nil {
		return fmt.Errorf("extracting current PCR values: %w", err)
	}

	// Get stored PCR values from SealedVolume's attestation spec
	if sealedVolume.Spec.Attestation == nil || sealedVolume.Spec.Attestation.PCRValues == nil {
		logger.Info("No PCR values stored during enrollment - skipping PCR verification")
		return nil
	}

	storedPCRs := sealedVolume.Spec.Attestation.PCRValues

	// Compare PCR values
	if err := comparePCRValues(storedPCRs, currentPCRs, logger); err != nil {
		return fmt.Errorf("PCR values changed since enrollment: %w", err)
	}

	logger.Info("PCR verification successful - boot state matches enrollment")
	return nil
}

// comparePCRValues compares stored and current PCR values
func comparePCRValues(stored, current *keyserverv1alpha1.PCRValues, logger logr.Logger) error {
	// Count how many PCR values are actually stored and current
	storedCount := countNonEmptyPCRs(stored)
	currentCount := countNonEmptyPCRs(current)

	logger.Info("PCR verification", "storedPCRs", storedCount, "currentPCRs", currentCount)

	// Case 1: No PCRs stored during enrollment - expect consistency
	if storedCount == 0 {
		if currentCount > 0 {
			logger.Info("PCR consistency violation - enrollment had no PCRs but current attestation provides PCRs")
			return fmt.Errorf("enrollment had empty PCRs but current attestation has PCR values - inconsistent state")
		}
		logger.Info("PCR verification: both enrollment and current attestation have empty PCRs - consistent")
		return nil
	}

	// Case 2: PCRs were stored during enrollment - strict verification required
	if currentCount == 0 {
		return fmt.Errorf("PCRs were stored during enrollment but none provided now - possible PCR extraction failure")
	}

	// Case 3: Compare actual PCR values using flexible PCR map
	storedPCRs := stored.PCRs
	currentPCRs := current.PCRs

	if storedPCRs == nil {
		storedPCRs = make(map[string]string)
	}
	if currentPCRs == nil {
		currentPCRs = make(map[string]string)
	}

	// Compare each stored PCR against current PCRs
	for pcrIndex, storedValue := range storedPCRs {
		if storedValue == "" {
			continue // Skip empty PCR values
		}

		currentValue, exists := currentPCRs[pcrIndex]
		if !exists || currentValue == "" {
			return fmt.Errorf("PCR%s was stored during enrollment but not provided now", pcrIndex)
		}

		if storedValue != currentValue {
			logger.Info("PCR mismatch", "pcr", pcrIndex, "stored", storedValue, "current", currentValue)
			return fmt.Errorf("PCR%s changed - boot state verification failed", pcrIndex)
		}
	}

	logger.Info("PCR verification successful - all stored PCRs match current values")
	return nil
}

// countNonEmptyPCRs counts how many PCR values are non-empty
func countNonEmptyPCRs(pcrs *keyserverv1alpha1.PCRValues) int {
	if pcrs == nil || pcrs.PCRs == nil {
		return 0
	}

	count := 0
	for _, value := range pcrs.PCRs {
		if value != "" {
			count++
		}
	}
	return count
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

func findVolumeFor(requestData PassphraseRequestData, volumeList *keyserverv1alpha1.SealedVolumeList) (*SealedVolumeData, *keyserverv1alpha1.SealedVolume) {
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
					volumeData := &SealedVolumeData{
						Quarantined:    v.Spec.Quarantined,
						SecretName:     secretName,
						SecretPath:     secretPath,
						VolumeName:     v.Name,
						PartitionLabel: p.Label,
					}
					return volumeData, &v
				}
			}
		}
	}

	return nil, nil
}

// errorMessage should be used when an error should be both, printed to the stdout
// and sent over the wire to the websocket client.
func errorMessage(conn *websocket.Conn, logger logr.Logger, theErr error, description string) {
	if theErr == nil {
		return
	}
	logger.Error(theErr, description)

	sendErrorResponse(conn, logger)
}

// securityRejection should be used for security-related rejections (PCR mismatches, quarantine, etc.)
// These are logged as INFO since they're expected security behavior, not application errors
func securityRejection(conn *websocket.Conn, logger logr.Logger, reason string, details string) {
	logger.Info("Security verification failed - rejecting attestation", "reason", reason, "details", details)
	sendErrorResponse(conn, logger)
}

// sendErrorResponse sends an error response to the client and closes the connection
func sendErrorResponse(conn *websocket.Conn, logger logr.Logger) {
	// Send error as ProofResponse to maintain protocol consistency
	// Empty passphrase with error message embedded
	errorResp := tpm.ProofResponse{
		Passphrase: []byte{}, // Empty passphrase indicates error
	}

	if err := conn.WriteJSON(errorResp); err != nil {
		logger.Error(err, "Failed to send error response to client")
	}

	// Also close the connection to signal error condition
	conn.Close()
}

func logRequestHandler(logger logr.Logger, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Info("Incoming request", "method", r.Method, "uri", r.URL.String(),
			"referer", r.Header.Get("Referer"), "userAgent", r.Header.Get("User-Agent"))

		h.ServeHTTP(w, r)
	})
}

// handleTPMAttestation is the refactored TPM attestation flow with clean narrative
func handleTPMAttestation(w http.ResponseWriter, r *http.Request, logger logr.Logger, reconciler *controllers.SealedVolumeReconciler, kclient *kubernetes.Clientset, namespace string) {
	// 1. Establish secure connection
	conn, partition, err := establishAttestationConnection(w, r, logger)
	if err != nil {
		return // Error already logged and handled
	}
	defer conn.Close()

	// 2. Perform TPM challenge-response authentication
	clientAttestation, tpmHash, err := performTPMAuthentication(conn, logger)
	if err != nil {
		return // Error already sent to client
	}

	// 3. Determine enrollment status and get/create volume
	enrollmentContext, err := determineEnrollmentContext(reconciler, namespace, tpmHash, partition, logger)
	if err != nil {
		errorMessage(conn, logger, err, "Enrollment context")
		return
	}

	// 4. Check if TPM is quarantined (reject immediately if so)
	if !enrollmentContext.IsNewEnrollment && enrollmentContext.VolumeData != nil && enrollmentContext.VolumeData.Quarantined {
		securityRejection(conn, logger, "TPM quarantined", "Access denied due to previous security violations")
		return
	}

	// 5. Verify attestation data using selective enrollment
	if err := verifyAttestationData(enrollmentContext, clientAttestation, logger); err != nil {
		securityRejection(conn, logger, "Attestation verification failed", err.Error())
		return
	}

	// 6. Handle enrollment: initial enrollment for new TPMs or re-enrollment updates for existing ones
	if enrollmentContext.IsNewEnrollment {
		// Perform initial TOFU enrollment for new TPMs
		if err := performInitialEnrollment(enrollmentContext, clientAttestation, reconciler, kclient, namespace, logger); err != nil {
			errorMessage(conn, logger, err, "Initial enrollment")
			return
		}
	} else {
		// Update attestation data for re-enrollment of existing TPMs
		if err := updateEnrollmentData(enrollmentContext, clientAttestation, reconciler, logger); err != nil {
			errorMessage(conn, logger, err, "Re-enrollment data update")
			return
		}
	}

	// 7. Retrieve and send passphrase
	if err := sendPassphrase(conn, enrollmentContext, kclient, namespace, logger); err != nil {
		errorMessage(conn, logger, err, "Passphrase delivery")
		return
	}

	logger.Info("TPM attestation completed successfully")
}

// performInitialEnrollment creates TOFU enrollment for new TPMs
func performInitialEnrollment(ctx *EnrollmentContext, attestation *ClientAttestation, reconciler *controllers.SealedVolumeReconciler, kclient *kubernetes.Clientset, namespace string, logger logr.Logger) error {
	logger.Info("Creating new TOFU enrollment")

	// Generate secret name and path for new enrollment using DefaultSecret logic
	volumeData := SealedVolumeData{
		PartitionLabel: ctx.Partition.Label,
		VolumeName:     fmt.Sprintf("tofu-%s", ctx.TPMHash[:8]),
	}
	secretName, secretPath := volumeData.DefaultSecret()

	// Generate secure passphrase for new enrollment
	passphrase, err := generateTOFUPassphrase()
	if err != nil {
		return fmt.Errorf("generating TOFU passphrase: %w", err)
	}

	// Create Kubernetes secret (or reuse if it already exists from a previous enrollment)
	logger.Info("Creating TOFU secret", "secretName", secretName, "secretPath", secretPath)
	actualPassphrase, err := createOrReuseTOFUSecret(kclient, namespace, secretName, secretPath, passphrase, logger)
	if err != nil {
		return fmt.Errorf("creating TOFU secret: %w", err)
	}

	// Create attestation data using initial TOFU logic (stores ALL provided PCRs)
	attestationSpec := createInitialTOFUAttestation(attestation.AK, attestation.PCRValues, logger)

	// Extract EK in PEM format for storage
	ekPEM, err := encodeEKToPEM(attestation.EK)
	if err != nil {
		return fmt.Errorf("encoding EK to PEM: %w", err)
	}
	attestationSpec.EKPublicKey = ekPEM

	// Create SealedVolume resource for future attestations
	if err := createTOFUSealedVolumeWithAttestation(reconciler, namespace, ctx.TPMHash, secretName, secretPath, ctx.Partition, attestationSpec); err != nil {
		return fmt.Errorf("creating TOFU SealedVolume: %w", err)
	}

	// Update the enrollment context with volume data for passphrase retrieval
	ctx.VolumeData = &SealedVolumeData{
		Quarantined:    false,
		SecretName:     secretName,
		SecretPath:     secretPath,
		VolumeName:     volumeData.VolumeName,
		PartitionLabel: volumeData.PartitionLabel,
	}

	logger.Info("TOFU enrollment completed", "secretName", secretName, "secretPath", secretPath, "passphraseSource", func() string {
		if actualPassphrase == passphrase {
			return "newly_generated"
		}
		return "reused_existing"
	}())
	return nil
}

// verifyAttestationData verifies AK and PCR data using selective enrollment
func verifyAttestationData(ctx *EnrollmentContext, attestation *ClientAttestation, logger logr.Logger) error {
	// Skip verification for new enrollments (TOFU - Trust On First Use)
	if ctx.IsNewEnrollment {
		logger.Info("New enrollment - skipping attestation verification (TOFU)")
		return nil
	}

	// For existing enrollments, perform security verification
	logger.Info("Existing enrollment - performing security verification")

	// Verify AK public key matches the enrolled one using selective enrollment
	if err := verifyAKMatchSelective(ctx.SealedVolume, attestation.AK, logger); err != nil {
		logger.Info("AK verification failed - potential TPM impersonation attempt", "details", err.Error())
		return fmt.Errorf("AK verification failed: %w", err)
	}

	// Verify PCR values match the enrolled ones using selective enrollment (boot state verification)
	if attestation.PCRValues != nil {
		if ctx.SealedVolume.Spec.Attestation != nil {
			if err := verifyPCRValuesSelective(ctx.SealedVolume.Spec.Attestation.PCRValues, attestation.PCRValues, logger); err != nil {
				logger.Info("PCR verification failed - boot state changed", "details", err.Error())
				return fmt.Errorf("PCR verification failed: %w", err)
			}
		} else {
			logger.Info("No stored attestation data for PCR verification - accepting current PCRs")
		}
	} else {
		logger.Info("No PCR data provided by client")
	}

	logger.Info("All attestation data verification successful")
	return nil
}

// updateEnrollmentData updates attestation data for re-enrollment of existing TPMs
func updateEnrollmentData(ctx *EnrollmentContext, attestation *ClientAttestation, reconciler *controllers.SealedVolumeReconciler, logger logr.Logger) error {
	// Update any re-enrollment mode fields (empty values)
	if ctx.SealedVolume.Spec.Attestation != nil {
		logger.Info("Updating attestation data for re-enrollment mode fields")

		if err := updateAttestationDataSelective(ctx.SealedVolume.Spec.Attestation, attestation.AK, attestation.PCRValues, logger); err != nil {
			return fmt.Errorf("updating selective attestation data: %w", err)
		}

		// Update the SealedVolume resource if changes were made
		if err := reconciler.Update(context.TODO(), ctx.SealedVolume); err != nil {
			return fmt.Errorf("updating SealedVolume with new attestation data: %w", err)
		}

		logger.Info("Successfully updated attestation data")
	} else {
		logger.Info("No attestation data to update")
	}

	return nil
}

// sendPassphrase retrieves and securely sends the passphrase to the client
func sendPassphrase(conn *websocket.Conn, ctx *EnrollmentContext, kclient *kubernetes.Clientset, namespace string, logger logr.Logger) error {
	// After performInitialEnrollment, VolumeData should always be populated
	if ctx.VolumeData == nil {
		return fmt.Errorf("no volume data available - enrollment may have failed")
	}

	// Get secret name and path from the enrolled volume data
	secretName, secretPath := ctx.VolumeData.DefaultSecret()
	logger.Info("Retrieving passphrase", "secretName", secretName, "tpmHash", ctx.TPMHash[:8])

	// Retrieve the secret
	secret, err := kclient.CoreV1().Secrets(namespace).Get(context.TODO(), secretName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("retrieving secret: %w", err)
	}

	secretData, exists := secret.Data[secretPath]
	if !exists {
		return fmt.Errorf("passphrase not found in secret at key: %s", secretPath)
	}

	// Send passphrase securely to client
	response := tpm.ProofResponse{
		Passphrase: secretData,
	}

	if err := conn.WriteJSON(response); err != nil {
		return fmt.Errorf("sending passphrase response: %w", err)
	}

	logger.Info("Passphrase sent successfully to client")
	return nil
}

// updateLastVerificationTimestamp updates the last verification time for an existing SealedVolume
func updateLastVerificationTimestamp(reconciler *controllers.SealedVolumeReconciler, namespace, tpmHash string) error {
	// This would need to be implemented in the reconciler to update the LastVerifiedAt field
	// For now, we'll log that it should be updated
	// NOTE: Reconciler method to update verification timestamps needs implementation
	return nil
}

// extractPCRValues extracts PCR values from a TPM quote for verification
func extractPCRValues(quote []byte) (*keyserverv1alpha1.PCRValues, error) {
	if len(quote) == 0 {
		return &keyserverv1alpha1.PCRValues{}, nil
	}

	// Parse the quote format from tmp-helpers with flexible PCR selection
	var quoteData struct {
		Quote struct {
			Version   string `json:"version"`
			Quote     []byte `json:"quote"`
			Signature []byte `json:"signature"`
		} `json:"quote"`
		PCRs map[int][]byte `json:"pcrs"`
	}

	if err := json.Unmarshal(quote, &quoteData); err != nil {
		return nil, fmt.Errorf("unmarshaling quote data: %w", err)
	}

	// Extract PCRs from the flexible map
	pcrValues := &keyserverv1alpha1.PCRValues{
		PCRs: make(map[string]string),
	}

	if quoteData.PCRs != nil {
		// Populate the flexible PCRs map
		for pcrIndex, pcrValue := range quoteData.PCRs {
			if len(pcrValue) > 0 {
				pcrValues.PCRs[fmt.Sprintf("%d", pcrIndex)] = fmt.Sprintf("%x", pcrValue)
			}
		}
	}

	// Validate that the quote contains valid PCR indices
	for pcrIndex := range quoteData.PCRs {
		if pcrIndex < 0 || pcrIndex > 23 {
			return nil, fmt.Errorf("invalid PCR index %d in quote (valid range: 0-23)", pcrIndex)
		}
	}

	return pcrValues, nil
}

// equalIntSlices compares two int slices for equality
func equalIntSlices(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

// verifyPCRValues compares current PCR values against stored expected values
func verifyPCRValues(current, expected *keyserverv1alpha1.PCRValues, logger logr.Logger) error {
	if expected == nil || expected.PCRs == nil {
		// No expected values stored (first-time enrollment), accept any values
		logger.Info("No expected PCR values stored, accepting current values")
		return nil
	}

	if current == nil || current.PCRs == nil {
		return fmt.Errorf("no current PCR values provided")
	}

	// Compare each expected PCR value
	for pcrIndex, expectedValue := range expected.PCRs {
		if expectedValue == "" {
			continue // Skip empty expected values
		}

		currentValue, exists := current.PCRs[pcrIndex]
		if !exists || currentValue == "" {
			return fmt.Errorf("PCR%s mismatch: expected %s, but not provided in current values", pcrIndex, expectedValue)
		}

		if expectedValue != currentValue {
			return fmt.Errorf("PCR%s mismatch: expected %s, got %s", pcrIndex, expectedValue, currentValue)
		}
	}

	logger.Info("PCR verification successful")
	return nil
}

// quarantineSealedVolume marks a SealedVolume as quarantined due to PCR verification failure
func quarantineSealedVolume(reconciler *controllers.SealedVolumeReconciler, namespace, tpmHash string, logger logr.Logger) error {
	// Find the SealedVolume by TPM hash
	volumeList := &keyserverv1alpha1.SealedVolumeList{}
	err := reconciler.List(context.TODO(), volumeList, client.InNamespace(namespace))
	if err != nil {
		return fmt.Errorf("listing sealed volumes for quarantine: %w", err)
	}

	for i, volume := range volumeList.Items {
		if volume.Spec.TPMHash == tpmHash {
			// Mark as quarantined
			volumeList.Items[i].Spec.Quarantined = true

			// Update the resource
			err := reconciler.Update(context.TODO(), &volumeList.Items[i])
			if err != nil {
				return fmt.Errorf("updating sealed volume to quarantine: %w", err)
			}

			logger.Info("SealedVolume quarantined due to PCR verification failure", "tpmHash", tpmHash)
			return nil
		}
	}

	return fmt.Errorf("SealedVolume not found for quarantine")
}

// getSealedVolumeByTPMHash retrieves the full SealedVolume resource by TPM hash
func getSealedVolumeByTPMHash(reconciler *controllers.SealedVolumeReconciler, namespace, tpmHash string) (*keyserverv1alpha1.SealedVolume, error) {
	volumeList := &keyserverv1alpha1.SealedVolumeList{}
	err := reconciler.List(context.TODO(), volumeList, client.InNamespace(namespace))
	if err != nil {
		return nil, fmt.Errorf("listing sealed volumes: %w", err)
	}

	for _, volume := range volumeList.Items {
		if volume.Spec.TPMHash == tpmHash {
			return &volume, nil
		}
	}

	return nil, fmt.Errorf("SealedVolume not found for TPM hash: %s", tpmHash)
}

// verifyAKMatchSelective compares the current AK public key with the enrolled one using selective enrollment logic
func verifyAKMatchSelective(sealedVolume *keyserverv1alpha1.SealedVolume, currentAK *attest.AttestationParameters, logger logr.Logger) error {
	// Get the stored AK from the SealedVolume's attestation spec
	if sealedVolume.Spec.Attestation == nil {
		return fmt.Errorf("no attestation data in SealedVolume for verification")
	}

	storedAKPEM := sealedVolume.Spec.Attestation.AKPublicKey

	// Empty stored AK = re-enrollment mode, accept any current AK
	if storedAKPEM == "" {
		logger.Info("AK re-enrollment mode: accepting any AK value")
		return nil
	}

	// Non-empty stored AK = enforcement mode, require exact match
	currentAKPEM, err := encodeAKToPEM(currentAK)
	if err != nil {
		return fmt.Errorf("encoding current AK to PEM: %w", err)
	}

	if storedAKPEM != currentAKPEM {
		logger.Info("AK mismatch detected in enforcement mode",
			"storedAKLength", len(storedAKPEM),
			"currentAKLength", len(currentAKPEM))
		return fmt.Errorf("AK public key does not match enrolled key - potential TPM impersonation")
	}

	logger.Info("AK verification successful - matches enrolled key")
	return nil
}

// verifyPCRValuesSelective compares current PCR values against stored expected values using selective enrollment logic
func verifyPCRValuesSelective(stored, current *keyserverv1alpha1.PCRValues, logger logr.Logger) error {
	// No stored values = accept any current values (first enrollment or no requirements)
	if stored == nil || stored.PCRs == nil {
		logger.Info("No expected PCR values stored, accepting current values")
		return nil
	}

	// No current values provided
	if current == nil || current.PCRs == nil {
		// Check if any stored PCRs are actually required (non-empty)
		for pcrIndex, storedValue := range stored.PCRs {
			if storedValue != "" {
				return fmt.Errorf("no current PCR values provided but PCR%s is required", pcrIndex)
			}
		}
		logger.Info("No current PCR values but all stored PCRs are in re-enrollment mode")
		return nil
	}

	// Compare each stored PCR value using selective enrollment logic
	for pcrIndex, storedValue := range stored.PCRs {
		if storedValue == "" {
			// Empty stored value = re-enrollment mode, accept any current value
			logger.V(1).Info("PCR re-enrollment mode", "pcr", pcrIndex)
			continue
		}

		// Non-empty stored value = enforcement mode, require exact match
		currentValue, exists := current.PCRs[pcrIndex]
		if !exists || currentValue == "" {
			return fmt.Errorf("PCR%s mismatch: expected %s, but not provided in current values", pcrIndex, storedValue)
		}

		if storedValue != currentValue {
			return fmt.Errorf("PCR%s changed - boot state verification failed: expected %s, got %s", pcrIndex, storedValue, currentValue)
		}

		logger.V(1).Info("PCR enforcement mode verification passed", "pcr", pcrIndex)
	}

	logger.Info("PCR verification successful using selective enrollment")
	return nil
}

// updateAttestationDataSelective updates empty attestation fields with current values during selective enrollment
func updateAttestationDataSelective(attestation *keyserverv1alpha1.AttestationSpec, currentAK *attest.AttestationParameters, currentPCRs *keyserverv1alpha1.PCRValues, logger logr.Logger) error {
	updated := false

	// Update AK if empty (re-enrollment mode)
	if attestation.AKPublicKey == "" && currentAK != nil {
		akPEM, err := encodeAKToPEM(currentAK)
		if err != nil {
			return fmt.Errorf("encoding AK to PEM for update: %w", err)
		}
		attestation.AKPublicKey = akPEM
		logger.Info("Updated AK public key during selective enrollment")
		updated = true
	}

	// Update PCR values if empty (re-enrollment mode)
	if attestation.PCRValues != nil && currentPCRs != nil && currentPCRs.PCRs != nil {
		if attestation.PCRValues.PCRs == nil {
			attestation.PCRValues.PCRs = make(map[string]string)
		}

		for pcrIndex, currentValue := range currentPCRs.PCRs {
			// Only update if stored value exists AND is empty (re-enrollment mode)
			// Omitted PCRs (not in the map) should be skipped entirely per spec
			if storedValue, exists := attestation.PCRValues.PCRs[pcrIndex]; exists && storedValue == "" {
				attestation.PCRValues.PCRs[pcrIndex] = currentValue
				logger.Info("Updated PCR value during selective enrollment", "pcr", pcrIndex)
				updated = true
			}
		}
	}

	if updated {
		// Update timestamps
		now := metav1.Now()
		attestation.LastVerifiedAt = &now
		logger.Info("Selective enrollment update completed")
	}

	return nil
}

// createInitialTOFUAttestation creates attestation spec for initial TOFU enrollment, storing ALL provided PCRs
func createInitialTOFUAttestation(currentAK *attest.AttestationParameters, currentPCRs *keyserverv1alpha1.PCRValues, logger logr.Logger) *keyserverv1alpha1.AttestationSpec {
	currentTime := metav1.Now()

	attestation := &keyserverv1alpha1.AttestationSpec{
		EnrolledAt:     &currentTime,
		LastVerifiedAt: &currentTime,
	}

	// Store AK if provided
	if currentAK != nil {
		if akPEM, err := encodeAKToPEM(currentAK); err == nil {
			attestation.AKPublicKey = akPEM
			logger.Info("Stored AK public key for initial TOFU enrollment")
		} else {
			logger.Error(err, "Failed to encode AK during TOFU enrollment")
		}
	}

	// Store ALL provided PCRs without filtering
	if currentPCRs != nil && currentPCRs.PCRs != nil {
		attestation.PCRValues = &keyserverv1alpha1.PCRValues{
			PCRs: make(map[string]string),
		}

		// Copy all PCRs - don't filter any out
		for pcrIndex, pcrValue := range currentPCRs.PCRs {
			attestation.PCRValues.PCRs[pcrIndex] = pcrValue
		}

		logger.Info("Stored ALL PCR values for initial TOFU enrollment",
			"pcrCount", len(attestation.PCRValues.PCRs),
			"pcrs", attestation.PCRValues.PCRs)
	}

	return attestation
}

// establishAttestationConnection upgrades HTTP to WebSocket and extracts partition info
func establishAttestationConnection(w http.ResponseWriter, r *http.Request, logger logr.Logger) (*websocket.Conn, PartitionInfo, error) {
	logger.V(1).Info("Debug: Attempting to upgrade HTTP connection to WebSocket", "remoteAddr", r.RemoteAddr)
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logger.Error(err, "upgrading connection for TPM attestation")
		return nil, PartitionInfo{}, err
	}

	logger.Info("Starting TPM attestation WebSocket flow")

	// Get partition details from headers (sent by client)
	partition := PartitionInfo{
		Label:      r.Header.Get("label"),
		DeviceName: r.Header.Get("name"),
		UUID:       r.Header.Get("uuid"),
	}
	logger.Info("Partition details from client", "label", partition.Label, "name", partition.DeviceName, "uuid", partition.UUID)

	return conn, partition, nil
}

// performTPMAuthentication proves the client possesses the TPM hardware by performing
// cryptographic challenge-response authentication. This prevents TPM impersonation attacks
// where an attacker has public keys but lacks access to the actual TPM chip with private keys.
// Returns authenticated TPM data and hash for secure enrollment decisions.
func performTPMAuthentication(conn *websocket.Conn, logger logr.Logger) (*ClientAttestation, string, error) {
	// Protocol Step 1: Receive client's EK and AK attestation data
	logger.Info("Waiting for client attestation data")
	var clientData struct {
		EKBytes []byte `json:"ek_bytes"`
		AKBytes []byte `json:"ak_bytes"`
	}
	if err := conn.ReadJSON(&clientData); err != nil {
		errorMessage(conn, logger, fmt.Errorf("reading attestation data: %w", err), "WebSocket read")
		return nil, "", fmt.Errorf("reading attestation data: %w", err)
	}
	logger.Info("Received attestation data from client")

	// Decode EK from PEM bytes
	ek, err := tpm.DecodeEK(clientData.EKBytes)
	if err != nil {
		errorMessage(conn, logger, fmt.Errorf("decoding EK from PEM: %w", err), "EK decode")
		return nil, "", fmt.Errorf("decoding EK from PEM: %w", err)
	}
	logger.Info("Successfully decoded EK from client")

	// Decode AK parameters from JSON bytes
	var akParams attest.AttestationParameters
	if err := json.Unmarshal(clientData.AKBytes, &akParams); err != nil {
		errorMessage(conn, logger, fmt.Errorf("unmarshaling AK parameters: %w", err), "AK decode")
		return nil, "", fmt.Errorf("unmarshaling AK parameters: %w", err)
	}
	logger.Info("Successfully decoded AK from client")

	// Get TPM hash for lookup/enrollment decisions
	tpmHash, err := tpm.DecodePubHash(ek)
	if err != nil {
		errorMessage(conn, logger, fmt.Errorf("computing TPM hash: %w", err), "TPM hash")
		return nil, "", fmt.Errorf("computing TPM hash: %w", err)
	}
	logger.Info("Client TPM hash", "hash", tpmHash)

	// Protocol Step 2: Generate challenge using go-attestation
	logger.Info("Generating TPM attestation challenge")
	secret, challengeBytes, err := tpm.GenerateChallenge(ek, &akParams)
	if err != nil {
		errorMessage(conn, logger, fmt.Errorf("generating challenge: %w", err), "Challenge generation")
		return nil, "", fmt.Errorf("generating challenge: %w", err)
	}

	// Protocol Step 3: Send challenge to client
	var challenge struct {
		EC *attest.EncryptedCredential `json:"EC"`
	}
	if err := json.Unmarshal(challengeBytes, &challenge); err != nil {
		errorMessage(conn, logger, fmt.Errorf("unmarshaling challenge: %w", err), "Challenge unmarshal")
		return nil, "", fmt.Errorf("unmarshaling challenge: %w", err)
	}

	challengeResp := tpm.AttestationChallengeResponse{
		Challenge: challenge.EC,
	}

	logger.Info("Sending challenge to client")
	if err := conn.WriteJSON(challengeResp); err != nil {
		errorMessage(conn, logger, fmt.Errorf("sending challenge: %w", err), "Challenge send")
		return nil, "", fmt.Errorf("sending challenge: %w", err)
	}

	// Protocol Step 4: Receive proof from client
	logger.Info("Waiting for client proof response")
	var proofReq tpm.ProofRequest
	if err := conn.ReadJSON(&proofReq); err != nil {
		errorMessage(conn, logger, fmt.Errorf("reading proof request: %w", err), "Proof read")
		return nil, "", fmt.Errorf("reading proof request: %w", err)
	}
	logger.Info("Received proof from client")

	// Protocol Step 5: Verify proof
	logger.Info("Validating challenge response")
	respBytes, err := json.Marshal(tpm.ChallengeResponse{Secret: proofReq.Secret})
	if err != nil {
		errorMessage(conn, logger, fmt.Errorf("marshaling response for validation: %w", err), "Response marshal")
		return nil, "", fmt.Errorf("marshaling response for validation: %w", err)
	}

	if err := tpm.ValidateChallenge(secret, respBytes); err != nil {
		logger.Error(err, "Challenge validation failed")
		securityRejection(conn, logger, "Challenge validation failed", err.Error())
		return nil, "", fmt.Errorf("challenge validation failed: %w", err)
	}
	logger.Info("Challenge validation successful")

	// Extract PCR values if provided
	var currentPCRs *keyserverv1alpha1.PCRValues
	if len(proofReq.PCRQuote) > 0 {
		logger.Info("Extracting PCR values from quote")
		pcrVals, err := extractPCRValues(proofReq.PCRQuote)
		if err != nil {
			logger.Error(err, "Failed to extract PCR values from quote")
			// PCR extraction failure is non-fatal for authentication
		} else {
			currentPCRs = pcrVals
		}
	} else {
		logger.Info("No PCR quote provided by client")
	}

	// Return authenticated client data
	clientAttestation := &ClientAttestation{
		EK:        ek,
		AK:        &akParams,
		PCRValues: currentPCRs,
		PCRQuote:  proofReq.PCRQuote,
	}

	return clientAttestation, tpmHash, nil
}

// determineEnrollmentContext checks for existing enrollment and creates context
func determineEnrollmentContext(reconciler *controllers.SealedVolumeReconciler, namespace, tpmHash string, partition PartitionInfo, logger logr.Logger) (*EnrollmentContext, error) {
	requestData := PassphraseRequestData{
		TPMHash:    tpmHash,
		Label:      partition.Label,
		DeviceName: partition.DeviceName,
		UUID:       partition.UUID,
	}

	volumeList := &keyserverv1alpha1.SealedVolumeList{}
	err := reconciler.List(context.TODO(), volumeList, client.InNamespace(namespace))
	if err != nil {
		return nil, fmt.Errorf("listing sealed volumes: %w", err)
	}

	existingVolume, existingSealedVolume := findVolumeFor(requestData, volumeList)
	isNewEnrollment := existingVolume == nil

	logger.Info("Determined enrollment context",
		"isNewEnrollment", isNewEnrollment,
		"tpmHash", tpmHash,
		"partitionLabel", partition.Label,
		"foundVolumes", len(volumeList.Items))

	return &EnrollmentContext{
		IsNewEnrollment: isNewEnrollment,
		SealedVolume:    existingSealedVolume,
		VolumeData:      existingVolume,
		TPMHash:         tpmHash,
		Partition:       partition,
	}, nil
}
