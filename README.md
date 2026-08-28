# SAST Toy Project

Ground Truth 기반으로 정적 분석기의 탐지 성능을 평가하는 학습용 SAST 프로젝트입니다.

## Initial Scope

* Multi-language extensible architecture

  * Python
  * Java
  * JavaScript

* First vertical slice

  * Python
  * CWE-95
  * AST-based analyzer
  * Direct `eval(...)` call detection

* Analyzer comparison

  * AST-based analyzer
  * Regex-based baseline

* Ground Truth evaluation

  * TP
  * FP
  * FN
  * TN
  * Precision
  * Recall

## Current Progress

현재 Python CWE-95를 대상으로 첫 번째 분석기를 구현하고 있습니다.

Python AST를 이용하여 직접적인 `eval(...)` 호출을 탐지하며, Ground Truth 데이터와 비교하여 탐지 성능을 평가합니다.

```text
Python Source
     |
     v
AST Analyzer
     |
     v
Detection Result
     |
     v
Ground Truth Comparison
     |
     v
TP / FP / FN / TN
     |
     v
Precision / Recall
```

함수 별칭, 데이터 흐름, 심볼 해석과 같은 고급 분석은 현재 범위에 포함하지 않으며, 기본 분석기의 한계를 확인한 이후 단계적으로 확장할 예정입니다.

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
      |               |
      |               v
      |        TP / FP / FN / TN
      |               |
      |               v
      |       Precision / Recall
      |
      +---------> Reporting
```

## External Workspace

비신뢰 ZIP, 압축 해제된 소스, 대용량 원본 데이터셋, 임시 분석 파일은 Git 저장소 외부에서 관리합니다.

Default workspace:

```text
~/sast-workspace/
```

구분:

* Git repository

  * 소스 코드
  * 분석기 코드
  * Rule
  * Ground Truth
  * 선정된 테스트 케이스
  * 연구 메모

* External workspace

  * 원본 ZIP
  * 대용량 데이터셋
  * 압축 해제된 소스
  * 임시 분석 파일

## Roadmap

1. Python CWE-95 AST Analyzer
2. Ground Truth 기반 성능 평가
3. Regex baseline과 AST Analyzer 비교
4. Secure Ingestion
5. Language Routing
6. 추가 CWE 및 Java / JavaScript 확장
