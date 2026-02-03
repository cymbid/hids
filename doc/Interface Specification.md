# 0. 공통 원칙

## 0.1 전송/직렬화 규칙

*   **로컬 IPC/내부 이벤트**: JSON Lines (1 line = 1 message) 기본
*   **성능 필요 시**: 동일 스키마를 CBOR/Protobuf로 대체 가능 (버전 필드 유지)
*   **모든 메시지**: UTF-8

### 시간

*   `ts_realtime` (ISO8601 or epoch ms): 보고/로그용
*   `ts_mono_ms` (monotonic ms): 판정/윈도우 계산용

## 0.2 버전/호환

*   모든 메시지에 `schema_ver` 포함 (예: "1.0")
*   필드 추가는 backward-compatible (unknown field 무시)
*   필드 삭제/의미 변경은 major bump

# 1. Collector → Core (Event Bus) 인터페이스

IDS 코어는 “수집기들이 밀어넣는” 표준 이벤트를 소비한다.

## 1.1 표준 이벤트 메시지: Event

*   **채널**: 내부 큐 (in-proc) 또는 로컬 Unix Socket `/run/evse-ids/event.sock`
*   **방식**: push (collector → ids core)

### 스키마

```json
{
  "schema_ver": "1.0",
  "msg_type": "event",
  "event_id": "uuid-or-monotonic-seq",
  "ts_realtime": "2026-01-28T09:10:11.123+09:00",
  "ts_mono_ms": 123456789,
  "source": "OCPP|CTRL|METER|SYS|INT|ISO15118",
  "event_type": "OCPP_ACTION|STATE_CHANGE|CONTACTOR|POWER_SAMPLE|INTEGRITY_CHANGE|TIME_JUMP|REBOOT|DISK_USAGE|ISO15118_EVENT",
  "connector_id": 1,
  "session_id": "optional-string",
  "severity_hint": "INFO|WARN|CRITICAL",
  "payload": { }
}
```

### 필수/선택

*   **필수**: `schema_ver`, `msg_type`, `event_id`, `ts_realtime`, `ts_mono_ms`, `source`, `event_type`, `payload`
*   **선택**: `connector_id`, `session_id`, `severity_hint`

### 에러 처리

*   **파싱 실패/필드 누락**: collector는 해당 라인을 drop하고 `collector_error` 로그 남김
*   **ids core**: unknown `event_type` 수신 시 `event_type=UNKNOWN`으로 기록 후 drop (또는 pass-through 정책)

# 2. OCPP Log Collector 인터페이스

## 2.1 입력: OCPP 스택 로그

*   **소스**: journald 또는 파일
    *   journald: unit name `ocpp.service` 등
    *   file: `/var/log/ocpp/ocpp.log`

## 2.2 출력: EventSpec 매핑

### 2.2.1 OCPP 액션 이벤트: `OCPP_ACTION`

```json
{
  "schema_ver": "1.0",
  "msg_type": "event",
  "source": "OCPP",
  "event_type": "OCPP_ACTION",
  "payload": {
    "ocpp_version": "2.0.1",
    "action": "Authorize|TransactionEvent|Reset|ChangeConfiguration|UpdateFirmware|SetNetworkProfile|GetLog|LogStatusNotification|SecurityEventNotification|...",
    "direction": "REQ|RESP",
    "message_id": "optional",
    "correlation_id": "optional",
    "status": "Accepted|Rejected|Error|Timeout|Unknown",
    "reason": "optional",
    "id_token_hash": "optional",
    "remote_party": {
      "ip": "optional",
      "cn": "optional",
      "tls": true
    },
    "fields": {
      "connector_id": 1,
      "transaction_id": "optional",
      "event_type": "Started|Updated|Ended",
      "trigger_reason": "optional",
      "firmware_url": "optional",
      "config_key": "optional",
      "config_value": "optional"
    }
  }
}
```

### 2.2.2 파서 규칙 (설정)

*   collector는 아래 설정으로 “로그 라인 → 필드” 추출
    *   `parse_rules[]`: 정규식/토큰 규칙
    *   `action_map`: 스택 로그의 키워드 → OCPP Action 정규화
*   **요구사항**: OCPP 2.1 확장 시 `action_map`과 `fields`만 추가하면 core 변경 없이 동작

# 3. Control Collector (제어부) 인터페이스

EVSE 제어부 (evse-ctrld)가 “권위있는 상태”를 IDS에 알려줌.

## 3.1 제어부 → IDS 이벤트 채널

*   **채널**: Unix datagram socket 권장
    *   `/run/evse-ctrld/pub.sock` (ctrld가 publish)
    *   ids가 subscribe 또는 단순 수신

### 3.1.1 상태 변화: `STATE_CHANGE`

```json
{
  "schema_ver": "1.0",
  "msg_type": "event",
  "source": "CTRL",
  "event_type": "STATE_CHANGE",
  "connector_id": 1,
  "session_id": "sess-abc",
  "payload": {
    "prev_state": "IDLE|CONNECTED|AUTHORIZED|CHARGING|STOPPING|FAULT",
    "new_state":  "IDLE|CONNECTED|AUTHORIZED|CHARGING|STOPPING|FAULT",
    "reason": "PlugIn|AuthOk|RemoteStart|LocalStart|Fault|UserStop|RemoteStop|Timeout|...",
    "fault_code": "optional"
  }
}
```

### 3.1.2 컨택터: `CONTACTOR`

```json
{
  "schema_ver": "1.0",
  "msg_type": "event",
  "source": "CTRL",
  "event_type": "CONTACTOR",
  "connector_id": 1,
  "session_id": "optional",
  "payload": {
    "state": "ON|OFF",
    "result": "OK|FAIL",
    "reason": "StartCharge|StopCharge|Fault|Manual|..."
  }
}
```

# 4. Meter Collector 인터페이스

## 4.1 샘플 이벤트: `POWER_SAMPLE`

*   **주기**: 기본 200~1000ms (configurable)

```json
{
  "schema_ver": "1.0",
  "msg_type": "event",
  "source": "METER",
  "event_type": "POWER_SAMPLE",
  "connector_id": 1,
  "session_id": "optional",
  "payload": {
    "v_mv": 230000,
    "i_ma": 16000,
    "p_mw": 3680000,
    "wh": 123456,
    "temp_c_x10": 250,
    "quality": "OK|STALE|ESTIMATED|ERROR"
  }
}
```

# 5. Integrity Collector (FIM) 인터페이스

## 5.1 설정/바이너리 변경: `INTEGRITY_CHANGE`

```json
{
  "schema_ver": "1.0",
  "msg_type": "event",
  "source": "INT",
  "event_type": "INTEGRITY_CHANGE",
  "payload": {
    "path": "/etc/evse/config.yaml",
    "object_type": "CONFIG|CERT|BINARY|SCRIPT",
    "old_hash": "hex",
    "new_hash": "hex",
    "hash_alg": "sha256",
    "change_channel": "UNKNOWN|LOCAL_CLI|LOCAL_UI|OCPP|OTA|PKG_MGR",
    "actor": "optional"
  }
}
```

## 5.2 시간 급변: `TIME_JUMP`

```json
{
  "schema_ver": "1.0",
  "msg_type": "event",
  "source": "SYS",
  "event_type": "TIME_JUMP",
  "payload": {
    "delta_ms": 600000,
    "old_time": "2026-01-28T09:10:00+09:00",
    "new_time": "2026-01-28T09:20:00+09:00",
    "ntp_source": "optional"
  }
}
```

# 6. ISO 15118 Collector 인터페이스 (확장)

## 6.1 SECC/PLC 이벤트: `ISO15118_EVENT`

```json
{
  "schema_ver": "1.0",
  "msg_type": "event",
  "source": "ISO15118",
  "event_type": "ISO15118_EVENT",
  "connector_id": 1,
  "session_id": "optional",
  "payload": {
    "standard": "15118-2|15118-20",
    "phase": "TLS|APP_HANDSHAKE|AUTH|CHARGE_PARAMS|POWER_DELIVERY|METERING|V2G",
    "code": "TLS_HANDSHAKE_FAIL|CERT_VERIFY_FAIL|CONTRACT_CERT_INVALID|SESSION_NEGOT_FAIL|...",
    "detail": {
      "tls_version": "optional",
      "cipher": "optional",
      "cert_subject": "optional",
      "reason": "optional"
    }
  }
}
```

# 7. IDS Core → Control IPC 인터페이스

IDS가 Degrade/Safe를 제어부에 “명령” 또는 “상태”로 전달.

## 7.1 채널

*   Unix stream socket: `/run/evse-ids/ctrl.sock`
*   제어부가 서버 (listen), IDS가 클라이언트 (connect) 권장

## 7.2 메시지 타입

### 7.2.1 모드 설정: `SET_MODE`

```json
{
  "schema_ver": "1.0",
  "msg_type": "ctrl_cmd",
  "cmd": "SET_MODE",
  "payload": {
    "degrade": true,
    "safe_lock": false,
    "duration_s": 600,
    "reason_rule_id": "EVSE-OCPP-010",
    "note": "UpdateFirmware detected"
  }
}
```

### 7.2.2 안전 정지 요청: `REQUEST_SAFE_STOP`

```json
{
  "schema_ver": "1.0",
  "msg_type": "ctrl_cmd",
  "cmd": "REQUEST_SAFE_STOP",
  "payload": {
    "connector_id": 1,
    "session_id": "sess-abc",
    "reason_rule_id": "EVSE-PWR-004",
    "stop_profile": "GRACEFUL"
  }
}
```

### 7.2.3 상태 조회: `GET_MODE` / 응답 `MODE_STATUS`

```json
{ "schema_ver": "1.0", "msg_type": "ctrl_cmd", "cmd": "GET_MODE", "payload": {} }
```

```json
{
  "schema_ver": "1.0",
  "msg_type": "ctrl_resp",
  "resp": "MODE_STATUS",
  "payload": {
    "degrade": true,
    "safe_lock": false,
    "until_ts": "2026-01-28T10:00:00+09:00",
    "active_reasons": ["EVSE-OCPP-010"]
  }
}
```

## 7.3 ACK 규칙

*   모든 `ctrl_cmd`는 제어부가 1회 응답
*   **성공**: `ctrl_resp` + `status=OK`
*   **실패**: `status=ERROR` + `error_code`, `error_msg`

# 8. IDS Core → OCPP Notifier 인터페이스

OCPP 스택이 별도 프로세스면 “IDS→스택” 호출이 필요.

## 8.1 채널 옵션

*   A) OCPP 스택에 로컬 API/플러그인 제공 (권장)
*   B) IDS가 OCPP outbound message를 파일/소켓으로 전달하고, 스택이 송신
*   여기서는 범용적으로 Unix socket `/run/ocpp-stack/ids_notify.sock`를 가정.

## 8.2 메시지: `SEND_SECURITY_EVENT`

```json
{
  "schema_ver": "1.0",
  "msg_type": "ocpp_notify",
  "cmd": "SEND_SECURITY_EVENT",
  "payload": {
    "ocpp_version": "2.0.1",
    "event_type": "EVSE-INT-001",
    "severity": "WARN|CRITICAL",
    "timestamp": "2026-01-28T09:10:11.123+09:00",
    "tech_info": "short text, <= 512 bytes",
    "connector_id": 1,
    "session_id": "optional",
    "evidence": {
      "key": "value"
    }
  }
}
```

## 8.3 응답: `SEND_RESULT`

```json
{
  "schema_ver": "1.0",
  "msg_type": "ocpp_resp",
  "resp": "SEND_RESULT",
  "payload": {
    "status": "OK|ERROR",
    "error_code": "optional",
    "error_msg": "optional",
    "message_id": "optional"
  }
}
```

**주의** (현실 포인트): `SecurityEventNotification`의 허용 필드/길이/인코딩은 스택 구현에 따라 제약이 있을 수 있어. 그래서 `tech_info`는 짧게, `evidence`는 축약 (해시/요약값) 형태가 안정적.

# 9. IDS Local Ops (운영) 인터페이스

## 9.1 채널

*   Unix socket `/run/evse-ids/op.sock` 또는 로컬 REST (127.0.0.1)

## 9.2 명령

### 9.2.1 상태 조회: `GET_STATUS`

```json
{ "schema_ver": "1.0", "msg_type": "op_cmd", "cmd": "GET_STATUS", "payload": {} }
```

**응답**:

```json
{
  "schema_ver": "1.0",
  "msg_type": "op_resp",
  "resp": "STATUS",
  "payload": {
    "uptime_s": 12345,
    "active_mode": { "degrade": false, "safe_lock": false },
    "last_alerts": [
      { "rule_id": "EVSE-PWR-003", "severity": "WARN", "count": 3, "last_seen": "..." }
    ],
    "queue_depth": 12
  }
}
```

### 9.2.2 정책 리로드: `RELOAD_CONFIG`

```json
{ "schema_ver": "1.0", "msg_type": "op_cmd", "cmd": "RELOAD_CONFIG", "payload": {} }
```

### 9.2.3 룰 enable/disable (선택): `SET_RULE_STATE`

```json
{
  "schema_ver": "1.0",
  "msg_type": "op_cmd",
  "cmd": "SET_RULE_STATE",
  "payload": { "rule_id": "EVSE-OCPP-010", "enabled": false }
}
```

# 10. 로그/증적 번들 인터페이스 (선택: GetLog 대응)

CSMS가 `GetLog`를 호출하면, OCPP 스택이 IDS에게 “번들 생성”을 요청할 수 있음.

## 10.1 채널

*   `/run/evse-ids/logbundle.sock`

## 10.2 요청: `BUILD_LOG_BUNDLE`

```json
{
  "schema_ver": "1.0",
  "msg_type": "log_cmd",
  "cmd": "BUILD_LOG_BUNDLE",
  "payload": {
    "request_id": "ocpp-getlog-123",
    "time_range": { "from": "2026-01-28T08:00:00+09:00", "to": "2026-01-28T09:10:00+09:00" },
    "include": ["IDS_LOG", "OCPP_LOG", "SYSLOG"],
    "filters": { "min_severity": "WARN", "rule_ids": [] }
  }
}
```

**응답**: `LOG_BUNDLE_READY`

```json
{
  "schema_ver": "1.0",
  "msg_type": "log_resp",
  "resp": "LOG_BUNDLE_READY",
  "payload": {
    "request_id": "ocpp-getlog-123",
    "path": "/var/lib/evse-ids/bundles/bundle-123.tgz",
    "sha256": "hex",
    "size_bytes": 1234567
  }
}
```

# 11. 보안 요구 (인터페이스 관점)

*   모든 Unix socket은 소유자/그룹 권한으로 접근 제어
    *   예: `evse-ids` 유저, `ocpp` 그룹, `ctrl` 그룹 분리
*   운영 명령 (`op_cmd`)은 로컬 인증 필요 (최소: 소켓 권한 + optional token)
*   IDS가 생성하는 파일 (bundle/log)은 권한 최소화 (600)

원하면 다음을 같이 만들어서 “개발 바로 착수” 가능한 패키지로 다듬어줄게.

*   위 인터페이스를 기준으로 각 모듈 책임/스레드 모델 (예: collector별 thread, core single-thread event loop)
*   Rule Engine 입력/출력 인터페이스 (룰 조건 DSL/구성 포맷)
*   OCPP 2.0.1 `SecurityEventNotification`에 맞춘 `event_type` 네이밍 규칙 + `techInfo` 템플릿 (길이 제한/필드 축약 규칙 포함)