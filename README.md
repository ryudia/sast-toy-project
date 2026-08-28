# SAST Toy Project

정적 분석(SAST)의 기본 구조를 직접 구현하고 이해하기 위한 학습용 Toy Project입니다.

현재 단계에서는 Python CWE-95를 대상으로 작은 분석기를 구현하고,
Ground Truth를 이용하여 Regex 기반 탐지와 AST 기반 탐지의 동작 차이를 확인합니다.

## Initial Scope

- Multi-language extensible architecture
  - Python
  - Java
  - JavaScript
- First analyzer
  - Python
  - CWE-95
  - Direct `eval(...)` call detection
- Analyzer comparison
  - AST-based analyzer
  - Minimal Regex baseline
- Ground Truth evaluation
  - TP / FP / FN / TN
  - Precision / Recall

## Current Progress

Python CWE-95를 대상으로 최소 AST Analyzer와 Regex baseline을 구현했습니다.

두 detector를 동일한 Ground Truth에 실행하여 텍스트 패턴 기반 탐지와
AST 기반 구조 탐지의 기본적인 동작 차이를 확인합니다.

```text
                Ground Truth
                    |
          +---------+---------+
          |                   |
          v                   v
   Regex Baseline       AST Analyzer
          |                   |
          +---------+---------+
                    |
                    v
             TP / FP / FN / TN
             Precision / Recall
```

현재 비교 결과:

| Detector | TP | FP | FN | TN | Precision | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Regex Baseline | 2 | 2 | 1 | 1 | 0.5000 | 0.6667 |
| AST Analyzer | 2 | 0 | 1 | 3 | 1.0000 | 0.6667 |

이 결과는 의도적으로 구성한 작은 Ground Truth에서 두 detector의 동작 차이를 확인한 결과이며,
일반적인 detector의 성능 우위를 의미하지 않습니다.

Alias Resolution, Name Binding, Data Flow와 같은 고급 분석은 현재 범위에 포함하지 않습니다.

## Architecture

```text
Untrusted Source
      |
      v
Secure Ingestion
      |
      v
Language Routing
      |
      v
SAST Analyzer
      |
      v
Raw Detection
      |
      v
Finding Normalizer
      |
      v
Normalized Finding
      |
      +---------> Evaluation <--------- Ground Truth
      |
      +---------> Reporting
```

## Run

분석기 비교:

```bash
python3 -m evaluator.run_evaluation
```

테스트:

```bash
python3 -m unittest discover -s tests -v
```

## External Workspace

비신뢰 ZIP, 압축 해제된 소스, 대용량 원본 데이터셋,
임시 분석 파일은 Git 저장소 외부에서 관리합니다.

```text
~/sast-workspace/
```

## Roadmap

### Completed

- Python CWE-95 최소 AST Analyzer
- 작은 Ground Truth 기반 동작 검증
- Minimal Regex baseline과 AST Analyzer 비교

### Next

1. Secure Ingestion
2. Language Routing
3. 추가 CWE 및 Java / JavaScript 확장

Alias Resolution, Name Binding, Data Flow와 같은 고급 분석은 현재 Roadmap에 포함하지 않습니다.
