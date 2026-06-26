// Command server is alpha/conformance: the ADR-073 self-service-resource conformance harness.
//
// It is a normal long-running HTTP service deployed via the platform's paved road. Beyond the cheap
// liveness/readiness endpoint the deployment probes (/healthz), it exposes /selftest, which — on demand —
// round-trips every cloud resource this Service's Environment claim declared, using ONLY the derived,
// platform-scoped IAM that EKS Pod Identity injects, and asserts that a non-granted call is denied. It proves
// the runtime path end to end: Pod Identity creds -> derived RolePolicy -> real S3/SQS/SNS/DynamoDB ops, plus
// tenancy isolation. Resource coordinates arrive via envFrom (the <svc>-resources ConfigMap the Crossplane
// Composition publishes).
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/smithy-go"
)

const probeKey = "adr-073-conformance-probe"

type checkResult struct {
	Name   string `json:"name"`
	Status string `json:"status"` // pass | fail | skipped
	Detail string `json:"detail"`
}

// newMux wires the routes — extracted so the unit test can exercise /healthz without binding a port or AWS.
func newMux(version, namespace string) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"app":       "alpha-conformance",
			"version":   version,
			"namespace": namespace,
			"hint":      "GET /selftest exercises the declared cloud resources via Pod Identity",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		})
	})

	// Cheap, local liveness/readiness — deliberately does NO AWS work (probes must not flap on AWS latency).
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// On-demand conformance: round-trip every declared engine via Pod-Identity creds + a negative isolation
	// check. Idempotent (each round-trip cleans up after itself), so it's safe to call repeatedly.
	mux.HandleFunc("GET /selftest", selftest)

	return mux
}

func selftest(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "load AWS config: " + err.Error()})
		return
	}

	var results []checkResult
	run := func(name, coordEnv string, fn func(ctx context.Context, cfg aws.Config, coord string) error) {
		coord := os.Getenv(coordEnv)
		if coord == "" {
			results = append(results, checkResult{name, "skipped", coordEnv + " unset (resource not declared / ConfigMap not yet mounted)"})
			return
		}
		if err := fn(ctx, cfg, coord); err != nil {
			results = append(results, checkResult{name, "fail", err.Error()})
		} else {
			results = append(results, checkResult{name, "pass", coord})
		}
	}

	run("s3 (blob)", "BLOB_BUCKET", s3RoundTrip)
	run("sqs (jobs)", "JOBS_QUEUE_URL", sqsRoundTrip)
	run("sns (events)", "EVENTS_TOPIC_ARN", snsPublish) // publish proves the SSE-topic KMS grant
	run("dynamodb (sessions)", "SESSIONS_TABLE", dynamoRoundTrip)

	// Tenancy / least-privilege: a non-granted account-level call MUST be denied.
	if err := expectDenied(ctx, cfg); err != nil {
		results = append(results, checkResult{"isolation (s3 ListBuckets denied)", "fail", err.Error()})
	} else {
		results = append(results, checkResult{"isolation (s3 ListBuckets denied)", "pass", "AccessDenied as expected"})
	}

	passed := true
	for _, c := range results {
		if c.Status == "fail" {
			passed = false
		}
	}
	status := http.StatusOK
	if !passed {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, map[string]any{"passed": passed, "checks": results, "timestamp": time.Now().UTC().Format(time.RFC3339)})
}

func s3RoundTrip(ctx context.Context, cfg aws.Config, bucket string) error {
	c := s3.NewFromConfig(cfg)
	body := []byte("conformance " + time.Now().UTC().Format(time.RFC3339Nano))
	// The org SCP `enforce-encryption` denies any PutObject without an explicit server-side-encryption header
	// (even though the bucket defaults to SSE-S3), so every upload to a paved-road bucket must set it.
	if _, err := c.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: aws.String(probeKey), Body: bytes.NewReader(body), ServerSideEncryption: s3types.ServerSideEncryptionAes256}); err != nil {
		return wrap("put", err)
	}
	out, err := c.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: aws.String(probeKey)})
	if err != nil {
		return wrap("get", err)
	}
	got, _ := io.ReadAll(out.Body)
	if !bytes.Equal(got, body) {
		return errors.New("get returned a different body than put")
	}
	if _, err := c.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: aws.String(probeKey)}); err != nil {
		return wrap("delete", err)
	}
	return nil
}

func sqsRoundTrip(ctx context.Context, cfg aws.Config, url string) error {
	c := sqs.NewFromConfig(cfg)
	msg := "conformance " + time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := c.SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: &url, MessageBody: &msg}); err != nil {
		return wrap("send", err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		out, err := c.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{QueueUrl: &url, MaxNumberOfMessages: 1, WaitTimeSeconds: 5})
		if err != nil {
			return wrap("receive", err)
		}
		for _, m := range out.Messages {
			if m.Body != nil && *m.Body == msg {
				if _, err := c.DeleteMessage(ctx, &sqs.DeleteMessageInput{QueueUrl: &url, ReceiptHandle: m.ReceiptHandle}); err != nil {
					return wrap("delete", err)
				}
				return nil
			}
		}
	}
	return errors.New("sent message not received within 20s")
}

func snsPublish(ctx context.Context, cfg aws.Config, topicArn string) error {
	out, err := sns.NewFromConfig(cfg).Publish(ctx, &sns.PublishInput{TopicArn: &topicArn, Message: aws.String("conformance probe")})
	if err != nil {
		return wrap("publish", err)
	}
	if out.MessageId == nil || *out.MessageId == "" {
		return errors.New("publish returned no MessageId")
	}
	return nil
}

func dynamoRoundTrip(ctx context.Context, cfg aws.Config, table string) error {
	c := dynamodb.NewFromConfig(cfg)
	item := map[string]ddbtypes.AttributeValue{
		"id":    &ddbtypes.AttributeValueMemberS{Value: probeKey},
		"stamp": &ddbtypes.AttributeValueMemberS{Value: time.Now().UTC().Format(time.RFC3339Nano)},
	}
	if _, err := c.PutItem(ctx, &dynamodb.PutItemInput{TableName: &table, Item: item}); err != nil {
		return wrap("put", err)
	}
	key := map[string]ddbtypes.AttributeValue{"id": &ddbtypes.AttributeValueMemberS{Value: probeKey}}
	got, err := c.GetItem(ctx, &dynamodb.GetItemInput{TableName: &table, Key: key, ConsistentRead: aws.Bool(true)})
	if err != nil {
		return wrap("get", err)
	}
	if len(got.Item) == 0 {
		return errors.New("get returned no item")
	}
	if _, err := c.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: &table, Key: key}); err != nil {
		return wrap("delete", err)
	}
	return nil
}

// expectDenied returns nil iff a non-granted call is rejected with AccessDenied (proving least privilege).
func expectDenied(ctx context.Context, cfg aws.Config) error {
	_, err := s3.NewFromConfig(cfg).ListBuckets(ctx, &s3.ListBucketsInput{})
	if err == nil {
		return errors.New("s3:ListAllMyBuckets SUCCEEDED — derived IAM is over-broad")
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "AccessDenied", "AccessDeniedException", "Forbidden":
			return nil
		}
	}
	return errors.New("expected AccessDenied, got: " + err.Error())
}

func wrap(op string, err error) error { return errors.New(op + ": " + err.Error()) }

func main() {
	version := getenv("VERSION", "dev")
	namespace := getenv("NAMESPACE", "unknown")

	srv := &http.Server{
		Addr:         ":8080",
		Handler:      newMux(version, namespace),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 120 * time.Second, // /selftest does live AWS round-trips
	}

	go func() {
		log.Printf("starting alpha-conformance version=%s namespace=%s", version, namespace)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	log.Println("shutting down (draining in-flight requests)…")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("graceful shutdown failed: %v", err)
	}
	log.Println("stopped")
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// canary incremental timing probe (trusted-ci#22)
