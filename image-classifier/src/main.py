import os
os.environ['JOBLIB_MULTIPROCESSING'] = '0'

import boto3, joblib, io, json, base64
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, classification_report

s3 = boto3.client("s3")
bucket = "ai-nids-models"

def load_model(name):
    obj = s3.get_object(Bucket=bucket, Key=f"models/{name}.pkl")
    return joblib.load(io.BytesIO(obj["Body"].read()))

# ML models — loaded once at module level, reused across warm invocations
rf  = load_model("rf")
xgb = load_model("xgb")
lr  = load_model("lr")
svm = load_model("svm")
mlp = load_model("mlp")

def load_artifact(name):
    obj = s3.get_object(Bucket=bucket, Key=f"train_params/{name}.pkl")
    return joblib.load(io.BytesIO(obj["Body"].read()))

# Preprocessing artifacts — loaded once from S3 at cold start
scaler          = load_artifact("robust_scaler")
label_encoders  = load_artifact("label_encoders")
x_cat_columns   = load_artifact("x_cat_columns")
x_quant_columns = load_artifact("x_quant_columns")

CATEGORICAL_FEATURES = [
    "IPV4_SRC_ADDR", "IPV4_DST_ADDR", "L4_SRC_PORT", "L4_DST_PORT",
    "PROTOCOL", "L7_PROTO", "TCP_FLAGS", "CLIENT_TCP_FLAGS", "SERVER_TCP_FLAGS",
    "ICMP_TYPE", "ICMP_IPV4_TYPE", "DNS_QUERY_ID", "DNS_QUERY_TYPE",
    "FTP_COMMAND_RET_CODE",
]
QUANTITATIVE_FEATURES = [
    "IN_BYTES", "OUT_BYTES", "IN_PKTS", "OUT_PKTS", "FLOW_DURATION_MILLISECONDS",
    "DURATION_IN", "DURATION_OUT", "MIN_TTL", "MAX_TTL", "LONGEST_FLOW_PKT",
    "SHORTEST_FLOW_PKT", "MIN_IP_PKT_LEN", "MAX_IP_PKT_LEN",
    "SRC_TO_DST_SECOND_BYTES", "DST_TO_SRC_SECOND_BYTES",
    "RETRANSMITTED_IN_BYTES", "RETRANSMITTED_IN_PKTS",
    "RETRANSMITTED_OUT_BYTES", "RETRANSMITTED_OUT_PKTS",
    "SRC_TO_DST_AVG_THROUGHPUT", "DST_TO_SRC_AVG_THROUGHPUT",
    "NUM_PKTS_UP_TO_128_BYTES", "NUM_PKTS_128_TO_256_BYTES",
    "NUM_PKTS_256_TO_512_BYTES", "NUM_PKTS_512_TO_1024_BYTES",
    "NUM_PKTS_1024_TO_1514_BYTES", "TCP_WIN_MAX_IN", "TCP_WIN_MAX_OUT",
    "DNS_TTL_ANSWER", "FLOW_START_MILLISECONDS", "FLOW_END_MILLISECONDS",
    "SRC_TO_DST_IAT_MIN", "SRC_TO_DST_IAT_MAX", "SRC_TO_DST_IAT_AVG",
    "SRC_TO_DST_IAT_STDDEV", "DST_TO_SRC_IAT_MIN", "DST_TO_SRC_IAT_MAX",
    "DST_TO_SRC_IAT_AVG", "DST_TO_SRC_IAT_STDDEV",
]


def clean_pcap_data(df):
    x_cat = df[[c for c in CATEGORICAL_FEATURES if c in df.columns]].copy()
    x_quant = df[[c for c in QUANTITATIVE_FEATURES if c in df.columns]].copy()

    # Expand TCP flag bitmasks into individual bit columns then drop originals
    x_cat = x_cat.drop(columns=["IPV4_SRC_ADDR", "IPV4_DST_ADDR"], errors="ignore")
    flag_cols = ["TCP_FLAGS", "CLIENT_TCP_FLAGS", "SERVER_TCP_FLAGS"]
    for col in [c for c in flag_cols if c in x_cat.columns]:
        for bit, name in enumerate(["FIN", "SYN", "RST", "PSH", "ACK", "URG"]):
            x_cat[f"{col}_{name}"] = x_cat[col].astype(int).apply(lambda v: v >> bit) & 1
    x_cat = x_cat.drop(columns=[c for c in flag_cols if c in x_cat.columns])

    for col in x_cat.columns:
        if col in label_encoders:
            le = label_encoders[col]
            known = set(le.classes_)
            x_cat[col] = x_cat[col].astype(str).apply(lambda v: v if v in known else le.classes_[0])
            x_cat[col] = le.transform(x_cat[col])
        else:
            x_cat[col] = 0

    low_card_cols = [col for col in x_cat.columns if x_cat[col].nunique() < 20]
    x_cat = pd.get_dummies(x_cat, columns=low_card_cols)
    x_cat = x_cat.reindex(columns=x_cat_columns, fill_value=0)

    for col in ["L4_SRC_PORT", "L4_DST_PORT"]:
        if col in x_cat.columns:
            freq = x_cat[col].value_counts()
            x_cat[col] = x_cat[col].map(freq)

    x_quant = x_quant.replace([np.inf, -np.inf], np.nan)
    x_quant = x_quant.dropna(axis=1, how="all")
    x_quant = x_quant.fillna(0)
    x_quant = x_quant.apply(lambda col: np.log1p(col) if (col >= 0).all() else col)
    upper = x_quant.quantile(0.99)
    x_quant = x_quant.clip(upper=upper, axis=1)
    x_quant = x_quant.reindex(columns=x_quant_columns, fill_value=0)
    x_quant = pd.DataFrame(scaler.transform(x_quant), columns=x_quant.columns)

    return pd.concat([x_cat.reset_index(drop=True), x_quant.reset_index(drop=True)], axis=1)


def handler(event, context):
    # Invoked directly by extractor Lambda with an S3 key
    if "s3_key" in event:
        obj = s3.get_object(Bucket=bucket, Key=event["s3_key"])
        df = pd.read_csv(io.BytesIO(obj["Body"].read()))
    else:
        # Invoked via API Gateway with a CSV body (direct upload path)
        body = event["body"]
        if event.get("isBase64Encoded"):
            body = base64.b64decode(body)
        df = pd.read_csv(io.BytesIO(body) if isinstance(body, bytes) else io.StringIO(body))
    df.drop_duplicates(inplace=True)
    df.dropna(inplace=True)
    df = df.reset_index(drop=True)

    y_test = df["Label"] if "Label" in df.columns else None
    X_test = clean_pcap_data(df.drop(columns=["Label"], errors="ignore"))

    results = {}
    for name, model in [("rf", rf), ("xgb", xgb), ("lr", lr), ("svm", svm), ("mlp", mlp)]:
        y_pred = model.predict(X_test)
        if y_test is not None:
            results[name] = {
                "confusion_matrix": confusion_matrix(y_test, y_pred, labels=[0, 1]).tolist(),
                "classification_report": classification_report(y_test, y_pred, labels=[0, 1], output_dict=True)
            }
        else:
            results[name] = {"predictions": y_pred.tolist()}

    return {
        "statusCode": 200,
        "headers": {"Access-Control-Allow-Origin": "*"},
        "body": json.dumps(results)
    }
