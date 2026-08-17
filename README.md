# k8s-forensics

Прототип системы криптографического обеспечения целостности цифровых доказательств при форензическом анализе в Kubernetes-кластерах. Разработан в рамках магистерской диссертации.

## Идея

Существующие инструменты форензики в Kubernetes (kube-forensics, Falco, osquery) умеют собирать артефакты, но не дают криптографических гарантий их целостности. Если злоумышленник получает доступ к кластеру, он может удалить логи, события или подменить конфигурацию — и доказать факт вмешательства постфактум нечем.

Этот прототип фиксирует каждый артефакт криптографически **в момент сбора**: хеширует SHA-3-512, подписывает постквантовым алгоритмом ML-DSA-65 (CRYSTALS-Dilithium) и связывает в хеш-цепочку. Даже если данные в кластере будут уничтожены, уже подписанные доказательства остаются проверяемыми.

## Компоненты

| Файл | Назначение |
|---|---|
| `agent/crypto_core.py` | Хеширование, подпись ML-DSA-65, построение и верификация хеш-цепочки |
| `agent/collector.py` | Сбор артефактов из Kubernetes API (поды, события, логи) |
| `agent/shredder.py` | Crypto-shredding — гарантированное уничтожение доказательств с сохранением непрерывности цепи |
| `dashboard/dashboard.py` | Веб-интерфейс верификации на Streamlit |
| `attack/attack_simulation.py` | Симуляция атак на доказательства |
| `manifests/daemonset.yaml` | Манифест развёртывания агента как DaemonSet |
| `Dockerfile` | Сборка образа агента |

## Технологии

- Python 3.11
- liboqs-python — постквантовая криптография (ML-DSA-65 / CRYSTALS-Dilithium, FIPS 204)
- SHA-3-512 (FIPS 202)
- kubernetes (Python client)
- SQLite
- Streamlit

## Быстрый старт

```bash
pip install -r requirements.txt --break-system-packages

cd agent
python3 -c "
from crypto_core import init_db, generate_or_load_keypair
from collector import load_k8s_config, run_collection_cycle
init_db(); generate_or_load_keypair(); load_k8s_config()
run_collection_cycle()
"

streamlit run dashboard/dashboard.py
```

### Развёртывание в кластере

```bash
docker build -t k8s-forensics-agent:latest .
minikube image load k8s-forensics-agent:latest
kubectl apply -f manifests/daemonset.yaml
```

## Результаты тестирования

Прототип протестирован в среде minikube (2 vCPU, 4 ГБ RAM).

| Метрика | Значение |
|---|---|
| VSR (Verification Success Rate) | 100% |
| FNR (False Negative Rate) | 0% |
| Среднее время подписи ML-DSA-65 | 3.16 мс |
| Потребление RAM агентом | 62.8 МБ |
| Потребление CPU (активный цикл) | 4.5% ядра |

Подробное описание методологии и полные результаты — в тексте диссертации.

## Статус

Учебный прототип для магистерской диссертации. Не предназначен для production-использования без доработки.

## Автор

MyDoomWorm 
