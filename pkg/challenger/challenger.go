package challenger

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	keyserverv1alpha1 "github.com/kairos-io/kairos-challenger/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tpm "github.com/kairos-io/go-tpm"
	"github.com/kairos-io/kairos-challenger/controllers"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
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

func Start(ctx context.Context, kclient *kubernetes.Clientset, reconciler *controllers.SealedVolumeReconciler, namespace, address string) {
	s := http.Server{
		Addr:         address,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	m := http.NewServeMux()

	m.HandleFunc("/challenge", func(w http.ResponseWriter, r *http.Request) {
		conn, _ := upgrader.Upgrade(w, r, nil) // error ignored for sake of simplicity

		for {

			fmt.Println("Received connection")
			volumeList := &keyserverv1alpha1.SealedVolumeList{}
			if err := reconciler.List(ctx, volumeList, &client.ListOptions{Namespace: namespace}); err != nil {
				fmt.Println("Failed listing volumes")
				fmt.Println(err)
				continue
			}

			token := r.Header.Get("Authorization")
			label := r.Header.Get("label")
			ek, at, err := tpm.GetAttestationData(token)
			if err != nil {
				fmt.Println("Failed getting tpm token")

				fmt.Println("error", err.Error())
				return
			}

			hashEncoded, err := tpm.DecodePubHash(ek)

			found := false
			var volume keyserverv1alpha1.SealedVolume
			for _, v := range volumeList.Items {
				if hashEncoded == v.Spec.TPMHash && v.Spec.Label == label {
					found = true
					volume = v
				}
			}

			if !found {
				fmt.Println("No TPM Hash found")
				continue
			}

			secret, challenge, err := tpm.GenerateChallenge(ek, at)
			if err != nil {
				fmt.Println("error", err.Error())
				return
			}

			resp, _ := writeRead(conn, challenge)

			if err := tpm.ValidateChallenge(secret, resp); err != nil {
				fmt.Println("error validating challenge", err.Error())
				return
			}

			writer, _ := conn.NextWriter(websocket.BinaryMessage)

			if !volume.Spec.Quarantined {

				secret, err := kclient.CoreV1().Secrets(namespace).Get(ctx, volume.Spec.Passphrase.Name, v1.GetOptions{})
				if err == nil {
					passphrase := secret.Data[volume.Spec.Passphrase.Path]
					json.NewEncoder(writer).Encode(map[string]string{"passphrase": string(passphrase)})

				}

			}
		}
	},
	)

	s.Handler = m

	go s.ListenAndServe()
	go func() {
		<-ctx.Done()
		s.Shutdown(ctx)
	}()
}
