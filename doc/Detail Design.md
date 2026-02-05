# 상세 설계 범위와 가정

## 1.1 범위

*   **evse-idsd(IDS 데몬) 중심 상세 설계**
*   **입력**: OCPP 스택 로그 + 제어부 IPC + 미터 샘플 + FIM/시스템 이벤트 + (확장) 15118 로그
*   **출력**: 로컬 로그/증적 + OCPP SecurityEventNotification + 제어부 IPC(Degrade/Safe)

## 1.2 가정

*   OCPP 스택은 별도 프로세스이며 로그를 journald 또는 파일로 남김
*   OCPP 스택은 IDS가 SecurityEventNotification을 보낼 수 있도록 로컬 API/플러그인/소켓 중 하나 제공 (명세는 소켓 기반으로 정의)
*   제어부(evse-ctrld)는 상태/컨택터/고장 이벤트 publish 및 명령 수신(SET_MODE/SAFE_STOP) 가능
*   15118 스택도 로그를 남기며, 이후 단계에서 파서 확장

# 컴포넌트 상세 설계

## 2.1 프로세스/서비스 구성

*   `evse-idsd.service` (systemd)
    *   `After=network.target ocpp-stack.service evse-ctrld.service`
    *   `Restart=on-failure`
    *   (옵션) `MemoryMax`, `CPUQuota`로 상한 설정

## 2.2 내부 모듈(코드 레벨)

*   `config/`: Config Loader / Validator
*   `collectors/`:
    *   `ocpp_log_collector`
    *   `control_collector`
    *   `meter_collector`
    *   `integrity_collector`
    *   `system_collector`
    *   `iso15118_collector`(확장)
*   `core/`:
    *   `event_bus(queue)`
    *   `normalizer(EventSpec)`
    *   `detection/` (fsm, rules, rate, integrity_evaluator)
    *   `alert_manager(dedupe/cooldown/aggregate)`
    *   `response_manager(policy mapping + actuation)`
*   `interfaces/`:
    *   `ctrl_ipc_client`
    *   `ocpp_notifier_client`
    *   `ops_api(unix socket/REST/CLI)`
    *   `log_bundle_builder(선택)`
*   `logging/`: jsonl writer, rotate, (옵션) hash-chain

# 스레드/이벤트 루프 설계

## 3.1 권장 구조: “Collector 스레드 + Core 단일 Event Loop”

*   Collector들은 입력을 비동기로 받아 Event Bus에 push
*   Core는 **단일 소비자(consumer)**로 이벤트를 순차 처리
    → FSM/레이트/윈도우 계산의 동시성 이슈를 최소화

### 스레드 구성

*   **Thread A**: OCPP Log Collector (tail/journald)
*   **Thread B**: Control Collector (subscribe socket)
*   **Thread C**: Meter Collector (timer tick)
*   **Thread D**: Integrity Collector (timer tick + inotify optional)
*   **Thread E**: System Collector (timer tick)
*   **Thread F**: (옵션) ISO15118 Collector
*   **Thread Main**: Core Event Loop (consume → normalize → detect → alert/response)

## 3.2 Event Bus 설계

*   고정 크기 ring-buffer + mutex/cond or lock-free MPSC queue
*   **Backpressure 정책**: queue full 시 drop policy 적용
    *   기본: 저가치 이벤트 우선 드랍 (예: `POWER_SAMPLE`는 샘플 다운샘플)
    *   고가치 이벤트 (`OCPP` 고위험/`INTEGRITY_CHANGE`/`STATE_CHANGE`)는 최대한 유지
*   Queue depth/드랍 카운트는 health metric으로 노출

# 데이터 모델 상세

## 4.1 EventSpec (표준 이벤트)

*   (앞서 인터페이스 명세의 Event 유지)
*   **필수 필드**: `event_id`, `ts_realtime`, `ts_mono_ms`, `source`, `event_type`, `payload`
*   **권장 공통 키**: `connector_id`, `session_id`

## 4.2 내부 상태(Context)

Core가 유지해야 하는 런타임 컨텍스트

### 4.2.1 ConnectorContext (커넥터별)

*   `fsm_state`
*   `current_session_id`
*   `contactor_state`
*   최근 계측 값: `last_v_mv`, `last_i_ma`, `last_p_mw`, `last_wh`
*   `last_sample_ts_mono`
*   최근 윈도우 통계(슬라이딩): P 평균/최대/최소, dP/dt 최대, `zero_power_duration` 등

### 4.2.2 RateLimitContext (룰별/키별)

*   **키 예**: (`AuthorizeFail`, `id_token_hash`), (`RemoteStart`, `connector_id`), (`Reset`, `global`)
*   저장 값: window counter or token bucket (tokens, `last_refill`)

### 4.2.3 IntegrityContext

*   watch 대상별 `last_hash`, `last_seen_ts`
*   `approved_change_window`(선택): “승인된 변경” 태그 유효시간

## 4.3 Alert 모델

*   `alert_key`(fingerprint): (`rule_id`, `connector_id`, `session_id`, `key_fields_hash`)
*   `first_seen`, `last_seen`, `count`
*   `severity`
*   `evidence`(축약된 핵심 필드)

# Collector 상세 설계

## 5.1 OCPP Log Collector

*   **입력**: journald(unit filter) 또는 파일(tail -F)
*   **처리**:
    *   라인 수신
    *   `parse_rules`(정규식/키워드)로 다음을 추출: `action`, `direction`, `status`, `reason`, `id_token_hash`, `message_id`, `fields{...}`
    *   `EventSpec OCPP_ACTION` 생성 후 bus push
*   **OCPP 2.1 확장**:
    *   `action_map`과 `fields_extractors`를 config로 분리
    *   unknown action은 `action="UNKNOWN"` + 원문 일부를 `fields.raw_hint`로 남김(길이 제한)

## 5.2 Control Collector

*   제어부 publish socket을 구독
*   `STATE_CHANGE`, `CONTACTOR` 이벤트를 그대로 EventSpec으로 변환
*   **“권위 소스” 정책**: 동일 시각 충돌 시 CTRL 이벤트를 우선(FSM 판단 기준)

## 5.3 Meter Collector

*   주기 `interval_ms` 설정
*   샘플 품질(`quality`) 포함
*   **다운샘플링 옵션**: queue 압박 시 1/N로 샘플 이벤트 생성
    *   대신 내부 통계는 계속 갱신 (가능하면 collector 쪽에서 집계해서 보내도 됨)

## 5.4 Integrity Collector(FIM)

*   **대상**: `config/binary/cert` 파일 allowlist
*   **메커니즘**: 주기 해시(기본) + (옵션) inotify로 변경 시점 캐치
*   변경 감지 시 `INTEGRITY_CHANGE` 이벤트 발행
*   **승인 변경(선택)**: 운영/업데이트 프로세스가 `approved_change_token`을 ops API로 넣으면 일정 시간 동안 변경을 “승인됨”으로 태깅

## 5.5 System Collector

*   **reboot**: `/proc/uptime` 또는 `boot-id` 변화
*   **disk**: log partition 사용량 임계 감시
*   **time jump**: realtime과 monotonic 차이를 이용 (또는 chrony 이벤트)

## 5.6 ISO15118 Collector(확장)

*   SECC 로그에서 카테고리화: TLS handshake fail, cert verify fail, session negotiation fail 등
*   `ISO15118_EVENT`로 정규화하여 bus로 전송

# Normalizer 상세 설계

## 6.1 역할

*   Collector 이벤트의 payload를 정규화된 키/단위로 통일
*   누락 필드 보완 (예: `connector_id`가 로그에 없으면 “최근 OCPP/CTRL 상태 기반 추정”은 MVP에서는 지양, 확장 단계에서만)

## 6.2 규칙

*   **단위 통일**: mV/mA/mW, Wh, temp_c_x10
*   문자열 enum 표준화 (대소문자/동의어 정리)
*   필드 길이 제한: raw log hint 최대 256~512 bytes

# Detection Engine 상세 설계

## 7.1 FSM Validator

### 상태 정의(기본)

*   `IDLE`, `CONNECTED`, `AUTHORIZED`, `CHARGING`, `STOPPING`, `FAULT`

### 허용 전이 테이블(예)

*   `IDLE` → `CONNECTED`
*   `CONNECTED` → `AUTHORIZED` / `IDLE`
*   `AUTHORIZED` → `CHARGING` / `IDLE`
*   `CHARGING` → `STOPPING` / `FAULT`
*   `STOPPING` → `IDLE` / `FAULT`
*   `FAULT` → `IDLE` (리커버리)

### 위반 처리

*   `EVSE-FSM-001` 등 룰 트리거
*   severity/정책은 policy mapping에 의해 결정

## 7.2 Rule Engine (임계/일관성)

*   룰은 “코드 룰 + 설정 파라미터” 구조로 구현

### 룰 실행 모델

*   `on_event(event)` 호출 시 해당 `event_type`에 매핑된 룰만 평가
    *   예: `POWER_SAMPLE` 도착 → PWR 룰들만
    *   `CONTACTOR` 도착 → 일관성 룰들
    *   `OCPP_ACTION` 도착 → OCPP 레이트/고위험 룰들

### 대표 룰 구현 포인트

*   **EVSE-PWR-003 (dP/dt)**: `dpdt = (P - prevP) / (t - prevT)`
    *   연속 N회 초과 시 severity 상승
*   **EVSE-PWR-004 (contactor OFF인데 P)**: `contactor_state=OFF` AND (`I > P threshold`) for `T` duration (바로 CRITICAL 또는 short debounce)

## 7.3 Rate Engine (윈도우/토큰버킷)

*   각 룰은 키 스키마 정의
*   구현 옵션:
    *   Window counter: `deque` of timestamps
    *   Token bucket: `refill_rate`, `burst`
*   **권장(MVP)**:
    *   window counter로 단순 구현
    *   메모리 상한을 위해 키 엔트리 LRU/TTL (예: 10분 미사용 키 제거)

## 7.4 Integrity Evaluator

*   `INTEGRITY_CHANGE` 발생 시 즉시 Alert 후보 생성
*   `change_channel`이 OCPP/OTA 등 승인 채널이면 severity 완화 가능 (정책으로)

# Alert Manager 상세 설계

## 8.1 Fingerprint(중복 억제 키)

*   기본: `rule_id` + `connector_id` + `session_id` + 주요 `evidence` 필드 해시
*   예: PWR 범위 위반은 (`rule_id`, `connector_id`)만으로도 충분
*   Auth fail 반복은 (`rule_id`, `id_token_hash`) 포함

## 8.2 Cooldown 정책

*   같은 fingerprint의 원격 전송은 `cooldown_s` 동안 1회
*   로컬 로그는 `count`만 증가시키고 `last_seen` 업데이트

## 8.3 Severity 상승 규칙(선택)

*   일정 시간 내 `count`가 높아지면 WARN→CRITICAL 승격 (룰별 설정)

# Response Manager 상세 설계

## 9.1 정책 테이블

*   `rule_id` → `action`(WARN_ONLY|DEGRADE|SAFE) + 파라미터(`duration`, `stop_profile`, `notify_min_sev`)
*   정책은 config에서 관리하고 런타임 reload 지원

## 9.2 Degrade 동작 정의

*   제어부에 `SET_MODE(degrade=1, duration, reason)` 전송
*   `degrade` 동안: 제어부가 새 세션 시작 제한/쿨다운 적용 (제어부 정책)
*   IDS는 고위험 알림(`Reset`/`UpdateFirmware` 등)을 계속 감시

## 9.3 Safe 동작 정의

*   제어부에 `REQUEST_SAFE_STOP(connector_id, session_id, reason)` 전송
*   IDS는 `safe_lock` 플래그를 유지할 수 있음 (다시 시작 방지)

## 9.4 실패 처리

*   IPC 실패 시: 로컬 로그 CRITICAL 기록
*   (가능하면) OCPP로 “IDS actuation failed” 이벤트 전송 (별도 rule/eventType)

# OCPP Notifier 상세 설계

## 10.1 입력

*   Alert Manager가 생성한 Alert

## 10.2 전송 조건

*   `min_severity` 이상 + `cooldown` 통과
*   `eventType` allowlist 통과 (운영 안전)

## 10.3 메시지 구성

*   `event_type`: 기본은 `rule_id` 사용 (권장)
*   `tech_info`: 512 bytes 이하 요약
*   `evidence`: 원문이 아닌 축약값 (예: 해시, 주요 수치 3~5개)

## 10.4 전송 경로

*   `ocpp_notifier_client`가 `/run/ocpp-stack/ids_notify.sock`로 JSON 메시지 송신
*   응답 `SEND_RESULT` 확인
*   실패 시 retry (지수 백오프, 최대 N회) 후 drop + 로컬 기록

# Log Bundle Builder(선택) 상세 설계

## 11.1 트리거

*   CSMS `GetLog` 요청 시 OCPP 스택이 IDS에 bundle 생성 요청

## 11.2 번들 구성

*   `/var/log/evse-ids/*.jsonl`
*   OCPP 스택 로그 일부 (시간 범위 필터)
*   syslog 일부 (시간 범위 필터)
*   메타: bundle manifest(json): 생성 시간, 포함 파일, sha256, 룰/알림 요약

## 11.3 보안

*   번들은 600 권한
*   업로드 후 보관 기간 정책 (예: 7일)으로 자동 삭제

# Local Ops API 상세 설계

## 12.1 채널

*   Unix socket `/run/evse-ids/op.sock` (로컬만)

## 12.2 기능

*   `GET_STATUS` (큐 depth, drop count, 최근 alerts, degrade/safe 상태)
*   `RELOAD_CONFIG`
*   (선택) `SET_RULE_STATE`, `SET_APPROVED_CHANGE_WINDOW`

## 12.3 접근 제어

*   소켓 권한 (UID/GID) + optional token
*   민감 명령 (룰 disable/승인 변경)은 추가 권한 요구

# 설정 파일 상세 (예: config.yaml 구조)

### 핵심 섹션

*   `collectors.ocpp_log`: `input`(journald/file), `parse_rules`, `action_map`
*   `collectors.meter`: `interval_ms`, `device`, `quality policy`
*   `collectors.integrity`: `watch_paths`, `hash_alg`, `interval_s`
*   `detection.fsm`: `states`, `transitions`
*   `detection.thresholds`: V/I/P limits, `dpdt`, `zero_power_timeout`
*   `detection.rate_limits`: rule별 `window`/`limit`
*   `alert.cooldown_s`, `alert.fingerprint_fields`
*   `response.mapping`: `rule_id` → `action` + parameters
*   `ocpp_notify`: `enabled`, `min_severity`, `allowlist`, `tech_info_template`

# 에러/예외 처리 설계

*   Collector 입력 파싱 실패: drop + `collector_error` 카운터 증가
*   Queue full: drop 정책 적용 + `drop` counter 증가
*   Normalizer 실패: `raw_hint`로 기록 후 drop
*   IPC 실패: `ctrl`: Safe/Degrade 전달 실패는 CRITICAL로 기록 + 원격 통지 (가능 시)
*   ocpp notifier: 재시도 후 실패 기록 (쿨다운 포함)

# 보안 설계 (구현 관점)

*   Unix socket 권한 최소화
*   `evse-idsd`는 rootless 권장 (디바이스 접근은 그룹 권한으로)
*   로그/번들 파일 600, 디렉토리 700
*   구성 파일 변경 감지 (FIM) 자체가 IDS 핵심이므로 config 파일도 watch 대상 포함

# 테스트 설계 (핵심 케이스)

## 16.1 단위

*   EventSpec 파싱/검증
*   FSM 전이 테이블
*   룰 계산 (`dP/dt`, `contactor` consistency)
*   rate limiter window/bucket
*   alert dedupe/cooldown

## 16.2 통합

*   OCPP 로그 재생(replay)로 RemoteStart 폭주/UpdateFirmware 탐지
*   충전 시퀀스 정상/비정상 (`FSM-001`)
*   미터 이상치/contactor mismatch (`PWR-004`)
*   FIM 변경 (`INTEGRITY_CHANGE`) → OCPP 알림 + Degrade

## 16.3 회복력

*   이벤트 폭주 시 queue drop 정책 검증
*   OCPP notifier 실패/복구
*   ctrl IPC 장애 시 로깅/재시도