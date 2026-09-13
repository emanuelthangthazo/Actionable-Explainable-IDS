# XIDS Model Evaluation Report

Per **WORKFLOW.md Section 6**, models are evaluated across Accuracy, Precision, Recall, F1-Score, Confusion Matrix, and ROC-AUC.
> **Note for IDS Workflows:** Recall is prioritized to minimize costly false negatives (missed intrusion attacks).

## Model Comparison Summary

| Model | Accuracy | Recall (Weighted) | Precision (Weighted) | F1-Score (Weighted) | ROC-AUC |
|---|---|---|---|---|---|
| **Random Forest** | 0.9984 | **0.9984** | 0.9984 | 0.9983 | 1.0000 |
| **Xgboost** | 0.9988 | **0.9988** | 0.9988 | 0.9988 | 1.0000 |

## Detailed Performance Breakdowns

### Random Forest

```text
                            precision    recall  f1-score   support

                    BENIGN       1.00      1.00      1.00    419012
                       Bot       0.92      0.51      0.65       390
                      DDoS       1.00      1.00      1.00     25603
             DoS GoldenEye       1.00      0.99      0.99      2057
                  DoS Hulk       1.00      1.00      1.00     34569
          DoS Slowhttptest       0.99      1.00      0.99      1046
             DoS slowloris       1.00      0.99      0.99      1077
               FTP-Patator       1.00      1.00      1.00      1186
                Heartbleed       1.00      0.50      0.67         2
              Infiltration       1.00      1.00      1.00         7
                  PortScan       0.99      1.00      0.99     18139
               SSH-Patator       1.00      0.99      1.00       644
  Web Attack � Brute Force       0.70      0.95      0.81       294
Web Attack � Sql Injection       1.00      0.25      0.40         4
          Web Attack � XSS       0.62      0.04      0.07       130

                  accuracy                           1.00    504160
                 macro avg       0.95      0.81      0.84    504160
              weighted avg       1.00      1.00      1.00    504160

```

**Confusion Matrix:**
```json
[[418771, 18, 1, 3, 15, 7, 0, 0, 0, 0, 196, 0, 1, 0, 0], [193, 197, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [8, 0, 25594, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [16, 0, 0, 2036, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [130, 0, 0, 2, 34436, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0], [0, 0, 0, 0, 0, 1042, 4, 0, 0, 0, 0, 0, 0, 0, 0], [10, 0, 0, 0, 0, 2, 1065, 0, 0, 0, 0, 0, 0, 0, 0], [2, 0, 0, 0, 0, 0, 0, 1183, 0, 0, 0, 0, 1, 0, 0], [1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0], [12, 0, 0, 0, 4, 0, 0, 0, 0, 0, 18121, 0, 2, 0, 0], [4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 640, 0, 0, 0], [12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 279, 0, 3], [3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0], [6, 0, 0, 0, 0, 1, 0, 0, 0, 0, 2, 0, 116, 0, 5]]
```

### Xgboost

```text
                            precision    recall  f1-score   support

                    BENIGN       1.00      1.00      1.00    419012
                       Bot       0.91      0.72      0.80       390
                      DDoS       1.00      1.00      1.00     25603
             DoS GoldenEye       1.00      0.99      1.00      2057
                  DoS Hulk       1.00      1.00      1.00     34569
          DoS Slowhttptest       0.99      1.00      0.99      1046
             DoS slowloris       0.99      0.99      0.99      1077
               FTP-Patator       1.00      1.00      1.00      1186
                Heartbleed       1.00      0.50      0.67         2
              Infiltration       1.00      1.00      1.00         7
                  PortScan       0.99      1.00      0.99     18139
               SSH-Patator       1.00      1.00      1.00       644
  Web Attack � Brute Force       0.71      0.98      0.83       294
Web Attack � Sql Injection       1.00      0.25      0.40         4
          Web Attack � XSS       0.75      0.12      0.20       130

                  accuracy                           1.00    504160
                 macro avg       0.96      0.84      0.86    504160
              weighted avg       1.00      1.00      1.00    504160

```

**Confusion Matrix:**
```json
[[418710, 28, 1, 4, 59, 9, 2, 1, 0, 0, 196, 0, 1, 0, 1], [109, 281, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [2, 0, 25601, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [8, 0, 0, 2043, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [4, 0, 0, 2, 34562, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0], [1, 0, 0, 0, 0, 1041, 4, 0, 0, 0, 0, 0, 0, 0, 0], [8, 0, 0, 0, 0, 3, 1066, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 1185, 0, 0, 0, 0, 0, 0, 1], [1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0], [5, 0, 0, 0, 4, 0, 0, 0, 0, 0, 18128, 0, 1, 0, 1], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 644, 0, 0, 0], [3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 289, 0, 2], [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0], [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 113, 0, 15]]
```
