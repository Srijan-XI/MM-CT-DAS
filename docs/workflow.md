# WORKFLOW.md
## MM-CT-DAS System Workflow

```yaml
# system_workflow.yaml
version: 1.0
name: MM-CT-DAS System Workflow
triggers:
  - event: telemetry_ingest
    description: "Triggered when network/host/app telemetry arrives"
components:
  - id: collector
    type: ingestion
    responsibilities:
      - capture telemetry (pcap, NetFlow, logs)
      - forward to message_bus
    outputs:
      - topic: raw_events

  - id: message_bus
    type: queue
    implementation_options: [kafka, pubsub]
    responsibilities:
      - durable buffering
      - replay support
    outputs:
      - topic: raw_events

  - id: preprocess
    type: stream_processor
    responsibilities:
      - normalize schema
      - deduplicate
      - sessionize
      - enrich_with_threat_intel
    inputs:
      - topic: raw_events
    outputs:
      - topic: enriched_events

  - id: feature_store_online
    type: online_store
    implementation_options: [redis, rocksdb]
    responsibilities:
      - store rolling-window features for real-time models
    inputs:
      - topic: enriched_events

  - id: feature_store_offline
    type: offline_store
    implementation_options: [s3, hdfs]
    responsibilities:
      - persist raw and engineered features for training
    inputs:
      - topic: enriched_events

  - id: model_inference
    type: model_fleet
    responsibilities:
      - run signature_engine
      - run rule_engine
      - run anomaly_models
      - run supervised_models
      - run deep_sequence_models
    inputs:
      - source: feature_store_online
      - source: enriched_events
    outputs:
      - topic: model_outputs

  - id: ensemble_fusion
    type: fusion_service
    responsibilities:
      - aggregate model_outputs
      - compute consolidated_score
      - attach provenance
    inputs:
      - topic: model_outputs
    outputs:
      - topic: consolidated_alerts

  - id: decision_engine
    type: policy_engine
    responsibilities:
      - map consolidated_score + context -> action
      - apply business rules and asset criticality
      - escalate to human if policy requires
    inputs:
      - topic: consolidated_alerts
    outputs:
      - topic: actions
      - topic: notifications

  - id: orchestration
    type: action_executor
    responsibilities:
      - execute mitigation via integrated adapters (FW, EDR, SDN)
      - log action and status
      - support automated rollback
    inputs:
      - topic: actions
    outputs:
      - topic: action_status

  - id: feedback_loop
    type: feedback
    responsibilities:
      - capture operator labels
      - capture sandbox / detonation results
      - update offline_store for retraining
    inputs:
      - topic: action_status
      - topic: notifications
    outputs:
      - job: retrain_pipeline

  - id: monitoring
    type: observability
    responsibilities:
      - metrics collection (latency, throughput, drift)
      - alert for model drift and abnormal behavior
    inputs:
      - topic: model_outputs
      - topic: action_status

sla:
  - name: high_severity_latency
    target: "<= 5s end-to-end for network telemetry path"
  - name: audit_retention
    target: "365 days immutable logs"

security:
  - data_encryption: in_transit_and_at_rest
  - access_control: role_based
  - key_management: central_kms

compliance:
  - gdpr: anonymization_option
  - pci: log_handling_constraints
```
