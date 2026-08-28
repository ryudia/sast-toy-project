# SAST Toy Project

Ground Truth 기반으로 정적 분석기의 탐지 성능을 평가하는 학습용 SAST 프로젝트.

## Initial Scope

- Multi-language extensible architecture
  - Python
  - Java
  - JavaScript
- First vertical slice
  - Python
  - CWE-95
  - Regex-based analyzer
- Ground Truth evaluation
  - TP
  - FP
  - FN
  - TN
  - Precision
  - Recall

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

## External Workspace

비신뢰 ZIP, 압축 해제된 소스, 대용량 원본 데이터셋,
임시 분석 파일은 Git 저장소 외부에서 관리한다.

Default workspace:

    ~/sast-workspace/

구분:

- Git repository: 소스코드, Rule, Ground Truth, 선정된 테스트 케이스, 연구 메모
- External workspace: 원본 ZIP, 대용량 데이터셋, 압축 해제물, 임시 파일
